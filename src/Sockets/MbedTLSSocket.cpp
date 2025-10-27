#include "pockethttp/Sockets/MbedTLSSocket.hpp"
#include "pockethttp/Sockets/certs.hpp"
#include "pockethttp/Logs.hpp"
#include "pockethttp/Timestamp.hpp"
#include "pockethttp/Buffer.hpp"
#include "pockethttp/SystemCerts.hpp"
#include "pockethttp/Results.hpp"

#ifdef USE_POCKET_HTTP_MBEDTLS


#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <stdio.h>

#if __has_include("mbedtls/ssl.h")
  extern "C" {
    #include <mbedtls/ssl.h>
    #include <mbedtls/x509_crt.h>
    #include <mbedtls/net_sockets.h>
    #include <mbedtls/error.h>
    #include <psa/crypto.h>
  }
#elif __has_include("mbedtls/mbedtls/ssl.h")
  extern "C" {
    #include <mbedtls/mbedtls/ssl.h>
    #include <mbedtls/mbedtls/x509_crt.h>
    #include <mbedtls/mbedtls/net_sockets.h>
    #include <mbedtls/mbedtls/error.h>
    #include <psa/crypto.h>
  }
#else
  #error "Cannot find mbedtls"
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  typedef SSIZE_T ssize_t;
#else
  #include <arpa/inet.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket(s) close(s)
#endif

namespace pockethttp {

  // Private/protected methods
  
  int MbedTLSSocket::psa_rng_wrapper(void * /*p_rng*/, unsigned char *buf, size_t len) {
    // psa_generate_random returns psa_status_t
    return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
  }

  bool MbedTLSSocket::loadCerts() {
    #ifdef USE_POCKET_HTTP_MOZILLA_ROOT_CERTS
      for (const std::vector<unsigned char>& derCert : pockethttp::MozillaCA::derCAs) {
        if (derCert.empty()) continue;

        const unsigned char *buf = derCert.data();
        size_t buf_len = derCert.size();

        int ret = mbedtls_x509_crt_parse_der(&this->cacert, buf, buf_len);
        if (ret != 0) {
          pockethttp_error("[MbedTLSSocket] Failed to parse DER certificate, mbedtls_x509_crt_parse_der returned: " << ret);
          return false;
        }
      }
    #endif // USE_POCKET_HTTP_MOZILLA_ROOT_CERTS

    auto der_list = pockethttp::SystemCerts::loadSystemCerts();
    for (const auto& derCert : der_list) {
      if (derCert.empty()) continue;

      const unsigned char *buf = derCert.data();
      size_t buf_len = derCert.size();

      int ret = mbedtls_x509_crt_parse_der(&this->cacert, buf, buf_len);
      if (ret != 0) {
        pockethttp_error("[MbedTLSSocket] Failed to parse DER certificate, mbedtls_x509_crt_parse_der returned: " << ret);
        return false;
      }
    }

    return true;
  }

  pockethttp::HttpResult MbedTLSSocket::initializeTLS(const std::string& hostname) {
    pockethttp_log("[MbedTLSSocket] Initializing TLS for hostname: " << hostname);
    int ret_code = 0;
    
    try {
      // Initialize MbedTLS structures
      mbedtls_ssl_init(&this->ssl);
      mbedtls_ssl_config_init(&this->conf);
      mbedtls_x509_crt_init(&this->cacert);
      mbedtls_net_init(&this->net_ctx);
      this->net_ctx.fd = this->socket_fd_;

      // Initialize PSA Crypto
      if (psa_crypto_init() != PSA_SUCCESS) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      // Load certs
      if (!this->loadCerts()) {
        return pockethttp::HttpResult::FAILED_TO_LOAD_CERTIFICATES;
      }
        
      // Configure SSL/TLS settings
      ret_code = mbedtls_ssl_config_defaults(
        &this->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
      );

      if (ret_code != 0) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      // Certificate verification required
      mbedtls_ssl_conf_authmode(&this->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
      mbedtls_ssl_conf_ca_chain(&this->conf, &this->cacert, nullptr);
      // mbedtls_ssl_conf_set_rng(&this->conf, this->psa_rng_wrapper, nullptr);

      ret_code = mbedtls_ssl_setup(&this->ssl, &this->conf);
      if (ret_code != 0) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      ret_code = mbedtls_ssl_set_hostname(&this->ssl, hostname.c_str()); /* SNI and verification */
      if (ret_code != 0) {
        this->disconnect();
        return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
      }

      mbedtls_ssl_set_bio(&this->ssl, &this->net_ctx, mbedtls_net_send, mbedtls_net_recv, nullptr);
      pockethttp_log("[MbedTLSSocket] TLS initialization successful");
      return pockethttp::HttpResult::SUCCESS;

    } catch (const std::exception& e) {
      pockethttp_error("[MbedTLSSocket] TLS initialization failed: " << e.what());
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }
  }

  pockethttp::HttpResult MbedTLSSocket::performTLSHandshake(const std::string& hostname) {
    pockethttp_log("[MbedTLSSocket] Starting TLS handshake for hostname: " << hostname);
    
    // Perform TLS handshake
    int ret_code = 0;
    while ((ret_code = mbedtls_ssl_handshake(&this->ssl)) != 0) {
      if (ret_code == MBEDTLS_ERR_SSL_WANT_READ || ret_code == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }

      char errbuf[256];
      mbedtls_strerror(ret_code, errbuf, sizeof(errbuf));
      pockethttp_error("[MbedTLSSocket] TLS handshake error: " << errbuf << " (" << ret_code << ")");
      this->disconnect();
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }

    uint32_t vrfy_flags = mbedtls_ssl_get_verify_result(&this->ssl);
    if (vrfy_flags != 0) {
      this->disconnect();
      return pockethttp::HttpResult::FAILED_TO_INIT_TLS;
    }

    pockethttp_log("[MbedTLSSocket] TLS handshake completed successfully");
    return pockethttp::HttpResult::SUCCESS;
  }

  void MbedTLSSocket::cleanupTLS() {
    pockethttp_log("[MbedTLSSocket] Cleaning up TLS resources");
    int ret_code = mbedtls_ssl_close_notify(&this->ssl);
    if (ret_code == MBEDTLS_ERR_SSL_WANT_READ || ret_code == MBEDTLS_ERR_SSL_WANT_WRITE) {
      // Try to close again
      int tmp = mbedtls_ssl_close_notify(&this->ssl);
      if (tmp != 0) {
        pockethttp_error("[MbedTLSSocket] Error during SSL close notify: " << tmp << ", original error: " << ret_code << ". Freeing resources anyway.");
      }
    }
    
    mbedtls_x509_crt_free(&this->cacert);
    mbedtls_ssl_free(&this->ssl);
    mbedtls_ssl_config_free(&this->conf);
    mbedtls_net_free(&this->net_ctx);
  }

  // Public methods

  MbedTLSSocket::MbedTLSSocket() {
    pockethttp_log("[MbedTLSSocket] MbedTLSSocket constructor called");

    this->connected_ = false;
    this->socket_fd_ = INVALID_SOCKET;
    this->last_used_timestamp_ = 0;
    
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
        pockethttp_log("[MbedTLSSocket] WinSock not initialized, throwing exception");
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  MbedTLSSocket::~MbedTLSSocket() {
    pockethttp_log("[MbedTLSSocket] MbedTLSSocket destructor called");
    this->disconnect();
  }

  pockethttp::HttpResult MbedTLSSocket::connect(const std::string& host, int port) {
    pockethttp_log("[MbedTLSSocket] Attempting to connect to " << host << ":" << port);

    if (this->connected_ || this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[MbedTLSSocket] Socket already connected, disconnecting first.");
      this->disconnect();
    }

    // Create TCP connection
    pockethttp::HttpResult open_state = this->openTCPSocket(host, port);
    if (open_state != pockethttp::HttpResult::SUCCESS || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[MbedTLSSocket] Failed to create TCP connection.");
      this->disconnect();
      if (open_state != pockethttp::HttpResult::SUCCESS) return open_state;
      else return pockethttp::HttpResult::OPEN_TCP_SOCKET_FAILED;
    }

    // Initialize TLS
    open_state = this->initializeTLS(host);
    if (open_state != pockethttp::HttpResult::SUCCESS) {
      pockethttp_error("[MbedTLSSocket] Failed to initialize TLS.");
      this->disconnect();
      return open_state;
    }

    // Perform TLS handshake
    open_state = this->performTLSHandshake(host);
    if (open_state != pockethttp::HttpResult::SUCCESS) {
      pockethttp_error("[MbedTLSSocket] TLS handshake failed.");
      this->disconnect();
      return open_state;
    }

    this->connected_ = true;
    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    pockethttp_log("[MbedTLSSocket] Successfully connected to " << host << ":" << port);
    return pockethttp::HttpResult::SUCCESS;
  }

  void MbedTLSSocket::disconnect() {
    if (this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[MbedTLSSocket] Disconnecting socket");

      this->cleanupTLS();
      closesocket(this->socket_fd_);
      this->socket_fd_ = INVALID_SOCKET;
      this->connected_ = false;
    }
}

  size_t MbedTLSSocket::send(const unsigned char* buffer, const size_t size) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[MbedTLSSocket] Cannot send data: socket not connected or SSL is invalid.");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[MbedTLSSocket] Sending " << size << " bytes.");

    // Send data using br_sslio_write_all for complete transmission
    int result = mbedtls_ssl_write(&this->ssl, buffer, size);
    if (result < 0 && result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
      pockethttp_error("[MbedTLSSocket] SSL write failed.");
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    pockethttp_log("[MbedTLSSocket] Data sent successfully.");
    return size;
  }

  size_t MbedTLSSocket::receive(unsigned char* buffer, size_t size, const int64_t& timeout) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[MbedTLSSocket] Cannot receive data: socket not connected or invalid SSL context.");
      return pockethttp::Buffer::error;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->socket_fd_, &read_fds);

    // Wait a short time period to see if there is data.
    // This avoids blocking indefinitely.
    struct timeval timeout_;
    timeout_.tv_sec = timeout / 1000; // seconds
    timeout_.tv_usec = (timeout % 1000) * 1000; // microseconds

    if (this->socket_fd_ == INVALID_SOCKET || this->socket_fd_ < 0) {
      pockethttp_error("[MbedTLSSocket] Select called with invalid socket: " << this->socket_fd_);
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    #ifndef _WIN32
      int flags = fcntl(this->socket_fd_, F_GETFL, 0);
      int status = fcntl(this->socket_fd_, F_GETFD);
      pockethttp_log("[MbedTLSSocket] Socket FD status: " << status << " (" << errno << ") " << strerror(errno) << ", flags: " << flags);
    #endif

    pockethttp_log("[MbedTLSSocket] Waiting for data with timeout: " << timeout << " ms on descriptor: " << this->socket_fd_);
    int select_result = select(this->socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout_);
    pockethttp_log("[MbedTLSSocket] Select result: " << select_result << " with descriptor: " << this->socket_fd_);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        pockethttp_error("[MbedTLSSocket] Select failed with error: " << WSAGetLastError());
      #else
        pockethttp_error("[MbedTLSSocket] Select failed with error: " << strerror(errno));
      #endif

      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (select_result == 0 || !FD_ISSET(this->socket_fd_, &read_fds)) {
      // No data or timeout, return Buffer error.
      pockethttp_error("[MbedTLSSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = mbedtls_ssl_read(&this->ssl, buffer, size);
    if (bytes_received == MBEDTLS_ERR_SSL_WANT_READ || bytes_received == MBEDTLS_ERR_SSL_WANT_WRITE) {
      // No data available right now
      pockethttp_log("[MbedTLSSocket] No data available for reading right now (WANT_READ/WRITE).");
      return 0;
    }

    if (bytes_received == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
      pockethttp_log("[MbedTLSSocket] Received new session ticket.");
      return 0;
    }

    if (bytes_received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      pockethttp_log("[MbedTLSSocket] SSL connection closed by peer");
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (bytes_received == 0) {
      pockethttp_log("[MbedTLSSocket] No data received, connection may be closed.");
      this->disconnect();
      return pockethttp::Buffer::error;
    }
    
    if (bytes_received < 0) {
      char errbuf[256];
      mbedtls_strerror(bytes_received, errbuf, sizeof(errbuf));
      pockethttp_error("[MbedTLSSocket] SSL read error: " << errbuf << " (" << bytes_received << ")");
      this->disconnect();
      return 0;
    }

    pockethttp_log("[MbedTLSSocket] Received " << bytes_received << " bytes.");
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    return bytes_received;
  }

  bool MbedTLSSocket::isConnected() {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_log("[MbedTLSSocket] Socket is not connected");
      return false;
    }
    
    // Check underlying TCP connection
    fd_set read_fds, error_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&error_fds);
    FD_SET(this->socket_fd_, &read_fds);
    FD_SET(this->socket_fd_, &error_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    
    int result = select(this->socket_fd_ + 1, &read_fds, nullptr, &error_fds, &timeout);
    if (result < 0) {
      pockethttp_error("[MbedTLSSocket] Select failed in isConnected check");
      this->disconnect();
      return false;
    }
    
    if (FD_ISSET(this->socket_fd_, &error_fds)) {
      pockethttp_error("[MbedTLSSocket] Socket error detected in isConnected check");
      this->disconnect();
      return false;
    }

    pockethttp_log("[MbedTLSSocket] TLS socket connection is healthy");
    return true;
  }
  
  int64_t MbedTLSSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp

#endif // USE_POCKET_HTTP_MBEDTLS