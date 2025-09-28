#ifndef POCKET_HTTP_TLS_SOCKET_HPP
#define POCKET_HTTP_TLS_SOCKET_HPP

#include "pockethttp/Sockets/SocketWrapper.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL

#include <cstdint>
#include <string>

// Include BearSSL headers directly instead of forward declarations
#if __has_include("bearssl.h")
  #include <bearssl.h>
#elif __has_include("bearssl/bearssl.h")
  #include <bearssl/bearssl.h>
#else
  #error "Cannot find bearssl.h or bearssl/bearssl.h"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
typedef int SOCKET;
#endif

namespace pockethttp {

  class TLSSocket : public SocketWrapper {
    private:
      br_x509_trust_anchor* trust_anchors_;
      size_t trust_anchors_count_;

      // BearSSL contexts - using raw pointers instead of unique_ptr for
      // incomplete types
      br_ssl_client_context* ssl_client_;
      br_x509_minimal_context* x509_context_;
      br_sslio_context* sslio_context_;
      unsigned char* iobuf_;

      // BearSSL I/O callbacks
      static int sock_read(void* ctx, unsigned char* buf, size_t len);
      static int sock_write(void* ctx, const unsigned char* buf, size_t len);

      // Helper methods
      bool loadCerts();
      bool initializeTLS(const std::string& hostname);
      bool performTLSHandshake(const std::string& hostname);
      void cleanupTLS();

    public:
      TLSSocket();
      ~TLSSocket() override;

      bool connect(const std::string& host, int port) override;
      void disconnect() override;

      size_t send(const unsigned char* buffer, const size_t size) override;
      size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) override;
      
      bool isConnected() override;
      int64_t getTimestamp() const override;
  };

} // namespace pockethttp

#endif // USE_POCKET_HTTP_BEARSSL

#endif // POCKET_HTTP_TLS_SOCKET_HPP