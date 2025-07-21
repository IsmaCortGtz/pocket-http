#ifndef POCKET_HTTP_SOCKETWRAPPER_HPP
#define POCKET_HTTP_SOCKETWRAPPER_HPP

#include <string>
#include <vector>

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
      virtual bool send(const std::vector<uint8_t>& data) = 0;
      virtual std::vector<uint8_t> receive() = 0;

      // Utility methods
      virtual bool isConnected() = 0;
      virtual int64_t getTimestamp() const = 0;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_SOCKETWRAPPER_HPP