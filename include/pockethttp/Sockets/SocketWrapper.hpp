#ifndef POCKET_HTTP_SOCKETWRAPPER_HPP
#define POCKET_HTTP_SOCKETWRAPPER_HPP

#include <string>
#include "pockethttp/Results.hpp"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <unistd.h>
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  #define closesocket(s) close(s)
#endif

namespace pockethttp {

#ifdef _WIN32
  class WinSockManager {
    public:
      static WinSockManager& getInstance();
      bool isInitialized() const;

    private:
      WinSockManager();
      ~WinSockManager();
      WinSockManager(const WinSockManager&) = delete;
      WinSockManager& operator=(const WinSockManager&) = delete;
      bool initialized_ = false;
  };
#endif

  class SocketWrapper {
    public:
      virtual ~SocketWrapper() = default;

      // Conection
      virtual pockethttp::HttpResult connect(const std::string& host, int port) = 0;
      virtual void disconnect() = 0;

      // Sending and receiving data
      virtual size_t send(const unsigned char* buffer, const size_t size) = 0;
      virtual size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) = 0;

      // Utility methods
      virtual bool isConnected() = 0;
      virtual int64_t getTimestamp() const = 0;
    
    protected:
      SOCKET socket_fd_ = INVALID_SOCKET;
      int64_t last_used_timestamp_ = 0;
      bool connected_ = false;

      pockethttp::HttpResult openTCPSocket(const std::string& host, int port);
  };

} // namespace pockethttp

#endif // POCKET_HTTP_SOCKETWRAPPER_HPP