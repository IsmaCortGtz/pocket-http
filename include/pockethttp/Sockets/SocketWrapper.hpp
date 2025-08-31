#ifndef POCKET_HTTP_SOCKETWRAPPER_HPP
#define POCKET_HTTP_SOCKETWRAPPER_HPP

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
      virtual bool connect(const std::string& host, int port) = 0;
      virtual void disconnect() = 0;

      // Sending and receiving data
      virtual size_t send(const unsigned char* buffer, const size_t size) = 0;
      virtual size_t receive(unsigned char* buffer, size_t size, const int64_t& timeout) = 0;

      // Utility methods
      virtual bool isConnected() = 0;
      virtual size_t getAvailableOutBytes() const = 0;
      virtual int64_t getTimestamp() const = 0;
    
      protected:
        SOCKET socket_fd_;
        int64_t last_used_timestamp_ = 0;
        bool connected_;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_SOCKETWRAPPER_HPP