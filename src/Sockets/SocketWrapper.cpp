#include <pockethttp/Sockets/SocketWrapper.hpp>
#ifdef POCKET_HTTP_LOGS
#include <iostream>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
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

#ifdef _WIN32
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
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] WinSock initialized successfully" << std::endl;
#endif
    } else {
#ifdef POCKET_HTTP_LOGS
      std::cerr << "[PocketHttp::TCPSocket] Failed to initialize WinSock" << std::endl;
#endif
    }
  }

  WinSockManager::~WinSockManager() {
    if (initialized_) {
      WSACleanup();
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] WinSock cleanup completed" << std::endl;
#endif
    }
  }
#endif

} // namespace pockethttp