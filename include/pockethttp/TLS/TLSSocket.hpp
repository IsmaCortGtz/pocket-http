#ifndef POCKET_HTTP_TLS_SOCKET_HPP
#define POCKET_HTTP_TLS_SOCKET_HPP

#ifdef POCKET_HTTP_USE_BEARSSL

#include <pockethttp/Sockets/SocketWrapper.hpp>
#include <cstdint>
#include <string>
#include <vector>

// Include BearSSL headers directly instead of forward declarations
#include "bearssl.h"

namespace pockethttp {

  class TLSSocket : public SocketWrapper {
    private:
      int socket_fd_;
      bool connected_;
      int64_t last_used_timestamp_;

      // BearSSL contexts - using raw pointers instead of unique_ptr for
      // incomplete types
      br_ssl_client_context* ssl_client_;
      br_x509_minimal_context* x509_context_;
      br_sslio_context* sslio_context_;
      unsigned char* iobuf_;

      // Helper methods
      bool initializeTLS(const std::string& hostname);
      void cleanupTLS();
      int createTCPConnection(const std::string& host, int port);
      bool performTLSHandshake(const std::string& hostname);

      // BearSSL I/O callbacks
      static int sock_read(void* ctx, unsigned char* buf, size_t len);
      static int sock_write(void* ctx, const unsigned char* buf, size_t len);

    public:
      TLSSocket();
      ~TLSSocket() override;

      // Non-copyable but movable
      TLSSocket(const TLSSocket&) = delete;
      TLSSocket& operator=(const TLSSocket&) = delete;
      TLSSocket(TLSSocket&& other) noexcept;
      TLSSocket& operator=(TLSSocket&& other) noexcept;

      // SocketWrapper interface implementation
      bool connect(const std::string& host, int port) override;
      void disconnect() override;
      bool send(const std::vector<uint8_t>& data) override;
      std::vector<uint8_t> receive() override;
      bool isConnected() override;
      int64_t getTimestamp() const override;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_USE_BEARSSL

#endif // POCKET_HTTP_TLS_SOCKET_HPP