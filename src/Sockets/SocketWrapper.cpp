#ifdef _WIN32
#include "pockethttp/Sockets/SocketWrapper.hpp"
#include "pockethttp/Logs.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;

namespace pockethttp {

  WinSockManager& WinSockManager::getInstance() {
    static WinSockManager instance;
    return instance;
  }

  bool WinSockManager::isInitialized() const {
    return initialized_;
  }

  WinSockManager::WinSockManager() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
      initialized_ = true;
      pockethttp_log("[TCPSocket] WinSock initialized successfully");
    } else {
      pockethttp_error("[TCPSocket] Failed to initialize WinSock");
    }
  }
  
  WinSockManager::~WinSockManager() {
    if (initialized_) {
      WSACleanup();
      pockethttp_log("[PocketHttp::TCPSocket] WinSock cleanup completed");
    }
  }

} // namespace pockethttp

#endif