#ifndef POCKET_HTTP_MBEDTLS_SOCKET_HPP
#define POCKET_HTTP_MBEDTLS_SOCKET_HPP

#include "pockethttp/Sockets/SocketWrapper.hpp"
#include "pockethttp/Results.hpp"

#ifdef USE_POCKET_HTTP_MBEDTLS

#include <cstdint>
#include <string>

// Include mbedtls headers directly instead of forward declarations
#if __has_include("mbedtls/ssl.h")
  extern "C" {
    #include <mbedtls/ssl.h>
    #include <mbedtls/x509_crt.h>
    #include <mbedtls/net_sockets.h>
    #include <psa/crypto.h>
  }
#elif __has_include("mbedtls/mbedtls/ssl.h")
  extern "C" {
    #include <mbedtls/mbedtls/ssl.h>
    #include <mbedtls/mbedtls/x509_crt.h>
    #include <mbedtls/mbedtls/net_sockets.h>
    #include <psa/crypto.h>
  }
#else
  #error "Cannot find mbedtls"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
typedef int SOCKET;
#endif

namespace pockethttp {

  class MbedTLSSocket : public SocketWrapper {
    private:
      mbedtls_ssl_context ssl;
      mbedtls_ssl_config conf;
      mbedtls_x509_crt cacert;
      mbedtls_net_context net_ctx;

      // Helper methods
      bool loadCerts();
      pockethttp::HttpResult initializeTLS(const std::string& hostname);
      pockethttp::HttpResult performTLSHandshake(const std::string& hostname);
      int psa_rng_wrapper(void * /*p_rng*/, unsigned char *buf, size_t len);
      void cleanupTLS();

    public:
      MbedTLSSocket();
      ~MbedTLSSocket() override;

      pockethttp::HttpResult connect(const std::string& host, int port) override;
      void disconnect() override;

      size_t send(const unsigned char* buffer, const size_t size) override;
      size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) override;
      
      bool isConnected() override;
      int64_t getTimestamp() const override;
  };

} // namespace pockethttp

#endif // USE_POCKET_HTTP_MBEDTLS

#endif // POCKET_HTTP_MBEDTLS_SOCKET_HPP