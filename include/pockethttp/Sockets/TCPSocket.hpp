#ifndef POCKET_HTTP_TCPSOCKET_HPP
#define POCKET_HTTP_TCPSOCKET_HPP

#include <pockethttp/Sockets/SocketWrapper.hpp>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
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

      bool send(const std::vector<uint8_t>& data) override;
      std::vector<uint8_t> receive() override;

      bool isConnected() override;
      int64_t getTimestamp() const override;

    protected:
      SOCKET socket_fd_;
      bool connected_;
      int64_t last_used_timestamp_;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_TCPSOCKET_HPP