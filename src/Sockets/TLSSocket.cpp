#include "pockethttp/Sockets/TLSSocket.hpp"
#include "pockethttp/Logs.hpp"
#include "pockethttp/Timestamp.hpp"
#include "pockethttp/Buffer.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL

#include "pockethttp/Sockets/certs.hpp"
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <stdio.h>
#include <bearssl/bearssl.h>

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

  int TLSSocket::sock_read(void* ctx, unsigned char* buf, size_t len) {
    SOCKET* socket_fd = static_cast<SOCKET*>(ctx);

    for (;;) {
      #ifdef _WIN32
        int rlen = recv(*socket_fd, reinterpret_cast<char*>(buf), len, 0);
      #else
        ssize_t rlen = read(*socket_fd, buf, len);
      #endif
        
      if (rlen <= 0) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error == WSAEINTR) continue;
        #else
          if (rlen < 0 && errno == EINTR) continue;
        #endif
        return -1;
      }
      return static_cast<int>(rlen);
    }
  }

  int TLSSocket::sock_write(void* ctx, const unsigned char* buf, size_t len) {
    SOCKET* socket_fd = static_cast<SOCKET*>(ctx);
    
    for (;;) {
      #ifdef _WIN32
        int wlen = ::send(*socket_fd, reinterpret_cast<const char*>(buf), len, 0);
      #else
        ssize_t wlen = write(*socket_fd, buf, len);
      #endif
        
      if (wlen <= 0) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error == WSAEINTR) continue;
        #else
          if (wlen < 0 && errno == EINTR) continue;
        #endif
        return -1;
      }
      return static_cast<int>(wlen);
    }
  }


  bool TLSSocket::loadCerts() {
    this->trust_anchors_ = (br_x509_trust_anchor*)TAs;
    this->trust_anchors_count_ = TAs_NUM;
    return true;
  }

  bool TLSSocket::initializeTLS(const std::string& hostname) {
    pockethttp_log("[TLSSocket] Initializing TLS for hostname: " << hostname);
    
    try {
      // Allocate contexts using malloc instead of new
      this->ssl_client_ = static_cast<br_ssl_client_context*>(malloc(sizeof(br_ssl_client_context)));
      this->x509_context_ = static_cast<br_x509_minimal_context*>(malloc(sizeof(br_x509_minimal_context)));
      this->sslio_context_ = static_cast<br_sslio_context*>(malloc(sizeof(br_sslio_context)));
        
      if (!this->ssl_client_ || !this->x509_context_ || !this->sslio_context_) {
        throw std::runtime_error("Failed to allocate TLS contexts.");
      }
        
      // Allocate I/O buffer
      this->iobuf_ = static_cast<unsigned char*>(malloc(BR_SSL_BUFSIZE_BIDI));
      if (!iobuf_) {
        throw std::runtime_error("Failed to allocate I/O buffer.");
      }

      // Load certs
      if (!this->loadCerts()) {
        throw std::runtime_error("Failed to load trust anchors.");
      }
        
      // Initialize the client context with full profile and X.509 validation
      br_ssl_client_init_full(this->ssl_client_, this->x509_context_, this->trust_anchors_, this->trust_anchors_count_);

      // Set the I/O buffer
      br_ssl_engine_set_buffer(&this->ssl_client_->eng, this->iobuf_, BR_SSL_BUFSIZE_BIDI, 1);
        
      // Reset the client context for new handshake
      br_ssl_client_reset(this->ssl_client_, hostname.c_str(), 0);
        
      // Initialize the simplified I/O wrapper context
      br_sslio_init(this->sslio_context_, &this->ssl_client_->eng, this->sock_read, &this->socket_fd_, this->sock_write, &this->socket_fd_);

      pockethttp_log("[TLSSocket] TLS initialization successful");
      return true;  
    } catch (const std::exception& e) {
      pockethttp_error("[TLSSocket] TLS initialization failed: " << e.what());
      return false;
    }
  }

  bool TLSSocket::performTLSHandshake(const std::string& hostname) {
    pockethttp_log("[TLSSocket] Starting TLS handshake for hostname: " << hostname);
    
    // Force handshake by attempting to flush
    if (br_sslio_flush(this->sslio_context_) < 0) {
      int ssl_err = br_ssl_engine_last_error(&this->ssl_client_->eng);
      pockethttp_error("[TLSSocket] TLS handshake failed during flush: " << ssl_err);
      return false;
    }
    
    // Check final state
    unsigned state = br_ssl_engine_current_state(&this->ssl_client_->eng);
    if (state == BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(&this->ssl_client_->eng);
      if (err != 0) {
        pockethttp_error("[TLSSocket] TLS handshake failed with SSL error: " << err);
        return false;
      }
    }

    pockethttp_log("[TLSSocket] TLS handshake completed successfully");
    return true;
  }

  void TLSSocket::cleanupTLS() {
    pockethttp_log("[TLSSocket] Cleaning up TLS resources");
    
    if (this->sslio_context_) {
      free(this->sslio_context_);
      this->sslio_context_ = nullptr;
    }
    
    if (this->ssl_client_) {
      free(this->ssl_client_);
      this->ssl_client_ = nullptr;
    }
    
    if (this->x509_context_) {
      free(this->x509_context_);
      this->x509_context_ = nullptr;
    }
    
    if (this->iobuf_) {
      free(this->iobuf_);
      this->iobuf_ = nullptr;
    }
  }

  // Public methods

  TLSSocket::TLSSocket() 
    : ssl_client_(nullptr),
      x509_context_(nullptr),
      sslio_context_(nullptr),
      iobuf_(nullptr) {
    pockethttp_log("[TLSSocket] TLSSocket constructor called");

    this->connected_ = false;
    this->socket_fd_ = INVALID_SOCKET;
    this->last_used_timestamp_ = 0;
    
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
        pockethttp_log("[TLSSocket] WinSock not initialized, throwing exception");
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  TLSSocket::~TLSSocket() {
    pockethttp_log("[TLSSocket] TLSSocket destructor called");
    this->disconnect();
  }

  bool TLSSocket::connect(const std::string& host, int port) {
    pockethttp_log("[TLSSocket] Attempting to connect to " << host << ":" << port);

    if (this->connected_ || this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TLSSocket] Socket already connected, disconnecting first.");
      this->disconnect();
    }

    // Create TCP connection
    bool open_state = this->openTCPSocket(host, port);
    if (!open_state || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TLSSocket] Failed to create TCP connection.");
      this->disconnect();
      return false;
    }

    // Initialize TLS
    if (!this->initializeTLS(host)) {
      pockethttp_error("[TLSSocket] Failed to initialize TLS.");
      this->disconnect();
      return false;
    }

    // Perform TLS handshake
    if (!performTLSHandshake(host)) {
      pockethttp_error("[TLSSocket] TLS handshake failed.");
      this->disconnect();
      return false;
    }

    this->connected_ = true;
    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    pockethttp_log("[TLSSocket] Successfully connected to " << host << ":" << port);
    return true;
  }

  void TLSSocket::disconnect() {
    if (this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TLSSocket] Disconnecting socket");
        
      // Properly close SSL connection if connected
      if (this->connected_ && this->sslio_context_) {
        // Try to send close_notify alert
        br_sslio_close(this->sslio_context_);
      }

      this->cleanupTLS();
      closesocket(this->socket_fd_);
      this->socket_fd_ = INVALID_SOCKET;
      this->connected_ = false;
    }
}

  size_t TLSSocket::send(const unsigned char* buffer, const size_t size) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET || !this->sslio_context_) {
      pockethttp_error("[TLSSocket] Cannot send data: socket not connected or SSL context invalid.");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[TLSSocket] Sending " << size << " bytes.");
    
    // Send data using br_sslio_write_all for complete transmission
    int result = br_sslio_write_all(this->sslio_context_, buffer, size);
    if (result < 0) {
      pockethttp_error("[TLSSocket] SSL write failed.");
      return pockethttp::Buffer::error;
    }
    
    // Flush the SSL buffer
    if (br_sslio_flush(this->sslio_context_) < 0) {
      pockethttp_error("[TLSSocket] SSL flush failed after write.");
      return pockethttp::Buffer::error;
    }
    
    this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    pockethttp_log("[TLSSocket] Data sent successfully.");
    return size;
  }

  size_t TLSSocket::receive(unsigned char* buffer, size_t size, const int64_t& timeout) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET || !this->sslio_context_) {
      pockethttp_error("[TLSSocket] Cannot receive data: socket not connected or invalid sslio context.");
      return pockethttp::Buffer::error;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->socket_fd_, &read_fds);

    // Wait a short time period to see if there is data.
    // This avoids blocking indefinitely.
    struct timeval timeout_;
    timeout_.tv_sec = 0; // 0s
    timeout_.tv_usec = timeout * 1000; // Xms (default 30000ms [30s])

    if (this->socket_fd_ == INVALID_SOCKET || this->socket_fd_ < 0) {
      pockethttp_error("[TLSSocket] Select called with invalid socket: " << this->socket_fd_);
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    #ifndef _WIN32
      int status = fcntl(this->socket_fd_, F_GETFD);
      pockethttp_log("[TLSSocket] Socket FD status: " << status << " (" << errno << ") " << strerror(errno));
    #endif

    pockethttp_log("[TLSSocket] Waiting for data with timeout: " << timeout << " ms on descriptor: " << this->socket_fd_);
    int select_result = select(this->socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout_);
    pockethttp_log("[TLSSocket] Select result: " << select_result << " with descriptor: " << this->socket_fd_);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        pockethttp_error("[TLSSocket] Select failed with error: " << WSAGetLastError());
      #else
        pockethttp_error("[TLSSocket] Select failed with error: " << strerror(errno));
      #endif

      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (select_result == 0 || !FD_ISSET(this->socket_fd_, &read_fds)) {
      // No data or timeout, return Buffer error.
      pockethttp_error("[TLSSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = br_sslio_read(this->sslio_context_, buffer, size);
    if (bytes_received < 0) {
      // Check if it's a SSL error or just no data available
      unsigned state = br_ssl_engine_current_state(&this->ssl_client_->eng);
      if (state == BR_SSL_CLOSED) {
        int err = br_ssl_engine_last_error(&this->ssl_client_->eng);
        if (err != 0) {
          pockethttp_error("[TLSSocket] SSL error during receive: " << err);
          this->disconnect();
        } else {
          pockethttp_log("[TLSSocket] SSL connection closed cleanly");
          this->disconnect();
        }
      }

      return pockethttp::Buffer::error;
    }
    
    if (bytes_received == 0) {
      // No data available or connection closed
      pockethttp_log("[TLSSocket] No data received, connection may be closed.");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[TLSSocket] Received " << bytes_received << " bytes.");
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();

    return bytes_received;
  }

  bool TLSSocket::isConnected() {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET || !this->sslio_context_) {
      pockethttp_log("[TLSSocket] Socket is not connected or SSL context is invalid");
      return false;
    }
    
    // Check SSL engine state
    unsigned state = br_ssl_engine_current_state(&this->ssl_client_->eng);
    
    if (state == BR_SSL_CLOSED) {
      int err = br_ssl_engine_last_error(&this->ssl_client_->eng);
      if (err != 0) {
        pockethttp_error("[TLSSocket] SSL engine is closed with error: " << err);
        this->disconnect();
        return false;
      }
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
      pockethttp_error("[TLSSocket] Select failed in isConnected check");
      this->disconnect();
      return false;
    }
    
    if (FD_ISSET(this->socket_fd_, &error_fds)) {
      pockethttp_error("[TLSSocket] Socket error detected in isConnected check");
      this->disconnect();
      return false;
    }
    
    pockethttp_log("[TLSSocket] TLS socket connection is healthy");
    return true;
  }
  
  int64_t TLSSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp

#endif // USE_POCKET_HTTP_BEARSSL