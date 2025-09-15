#ifndef POCKET_HTTP_TCPSOCKET_HPP
#define POCKET_HTTP_TCPSOCKET_HPP

#include "pockethttp/Sockets/SocketWrapper.hpp"
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
typedef int SOCKET;
#endif

namespace pockethttp {

  class TCPSocket : public pockethttp::SocketWrapper {
    public:
      TCPSocket();
      ~TCPSocket() override;

      bool connect(const std::string& host, int port) override;
      void disconnect() override;

      size_t send(const unsigned char* buffer, const size_t size) override;
      size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) override;

      bool isConnected() override;
      int64_t getTimestamp() const override;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_TCPSOCKET_HPP