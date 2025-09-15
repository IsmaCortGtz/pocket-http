#include "pockethttp/Sockets/SocketWrapper.hpp"
#include "pockethttp/Logs.hpp"

#include <string>
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <chrono>
#include <vector>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <sys/ioctl.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>  
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
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
        pockethttp_log("[WinSockManager] WinSock initialized successfully");
      } else {
        pockethttp_error("[WinSockManager] Failed to initialize WinSock");
      }
    }
    
    WinSockManager::~WinSockManager() {
      if (initialized_) {
        WSACleanup();
        pockethttp_log("[WinSockManager] WinSock cleanup completed");
      }
    }
  #endif // _WIN32

  bool SocketWrapper::openTCPSocket(const std::string& host, int port) {
    pockethttp_log("[SocketWrapper] Attempting to connect to " << host << ":" << port);

    if (connected_ || socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[SocketWrapper] Socket already connected, disconnecting first");
      disconnect();
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
      pockethttp_error("[SocketWrapper] Failed to resolve hostname: " << host);
      return false;
    }

    pockethttp_log("[SocketWrapper] Hostname resolved successfully");
    std::vector<struct addrinfo*> ipv4_addresses;
    std::vector<struct addrinfo*> ipv6_addresses;
    
    for (struct addrinfo* addr_ptr = result; addr_ptr != nullptr; addr_ptr = addr_ptr->ai_next) {
      if (addr_ptr->ai_family == AF_INET) {
        ipv4_addresses.push_back(addr_ptr);
      } else if (addr_ptr->ai_family == AF_INET6) {
        ipv6_addresses.push_back(addr_ptr);
      }
    }

    pockethttp_log(
      "[SocketWrapper] Found " << ipv4_addresses.size() << " IPv4 addresses and " 
      << ipv6_addresses.size() << " IPv6 addresses"
    );

    size_t ipv4_tried = 0;
    size_t ipv6_tried = 0;
    
    while (ipv4_tried < ipv4_addresses.size() || ipv6_tried < ipv6_addresses.size()) {
      std::vector<SOCKET> sockets;
      std::vector<struct addrinfo*> addresses;
        
      for (int i = 0; i < 2 && ipv4_tried < ipv4_addresses.size(); ++i, ++ipv4_tried) {
        addresses.push_back(ipv4_addresses[ipv4_tried]);
      }
        
      if (ipv6_tried < ipv6_addresses.size()) {
        addresses.push_back(ipv6_addresses[ipv6_tried]);
        ipv6_tried++;
      }
        
      while (addresses.size() < 3 && ipv6_tried < ipv6_addresses.size()) {
        addresses.push_back(ipv6_addresses[ipv6_tried]);
        ipv6_tried++;
      }

      pockethttp_log("[SocketWrapper] Attempting parallel connection to " << addresses.size() << " addresses");

      for (auto addr_ptr : addresses) {
        SOCKET sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
        
        if (sock == INVALID_SOCKET) {
          pockethttp_error("[SocketWrapper] Failed to create socket");
          continue;
        }
            
        #ifdef _WIN32
          unsigned long mode = 1;
          ioctlsocket(sock, FIONBIO, &mode);
        #else
          int flags = fcntl(sock, F_GETFL, 0);
          fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        #endif
            
        int connect_result = ::connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen);
        if (connect_result == SOCKET_ERROR) {
          #ifdef _WIN32
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
              pockethttp_error("[SocketWrapper] Connect failed with error: " << error);
              closesocket(sock);
              continue;
            }
          #else
            if (errno != EINPROGRESS) {
              pockethttp_error("[SocketWrapper] Connect failed: " << strerror(errno));
              closesocket(sock);
              continue;
            }
          #endif
        }
            
        sockets.push_back(sock);
      }
        
      if (sockets.empty()) {
        pockethttp_error("[SocketWrapper] No sockets created for this batch");
        continue;
      }
        
      fd_set write_fds, error_fds;
      struct timeval timeout;
      timeout.tv_sec = 3;
      timeout.tv_usec = 0;
        
      while (!sockets.empty()) {
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
            
        SOCKET max_fd = 0;
        for (SOCKET sock : sockets) {
          FD_SET(sock, &write_fds);
          FD_SET(sock, &error_fds);
          #ifndef _WIN32
            if (sock > max_fd) max_fd = sock;
          #endif
        }
            
        #ifdef _WIN32
          int select_result = select(0, nullptr, &write_fds, &error_fds, &timeout);
        #else
          int select_result = select(max_fd + 1, nullptr, &write_fds, &error_fds, &timeout);
        #endif
            
        if (select_result == SOCKET_ERROR) {
          pockethttp_error("[SocketWrapper] Select failed during connection");
          break;
        }
        if (select_result == 0) {
          pockethttp_log("[SocketWrapper] Connection timeout");
          break;
        }
            
        for (size_t i = 0; i < sockets.size(); ++i) {
          SOCKET sock = sockets[i];
                
          if (FD_ISSET(sock, &error_fds)) {
            pockethttp_error("[SocketWrapper] Socket error detected");
            closesocket(sock);
            sockets.erase(sockets.begin() + i);
            addresses.erase(addresses.begin() + i);
            --i;
            continue;
          }
                
          if (FD_ISSET(sock, &write_fds)) {
            int error = 0;
            socklen_t error_len = sizeof(error);
                    
            #ifdef _WIN32
              int sockopt = (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_len) == 0 && error == 0);
            #else
              int sockopt = (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 && error == 0);
            #endif

            if (sockopt) {
              char addr_str[INET6_ADDRSTRLEN];
              void* addr;
              if (addresses[i]->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)addresses[i]->ai_addr;
                addr = &(ipv4->sin_addr);
              } else {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addresses[i]->ai_addr;
                addr = &(ipv6->sin6_addr);
              }
                
              inet_ntop(addresses[i]->ai_family, addr, addr_str, INET6_ADDRSTRLEN);
              pockethttp_log("[SocketWrapper] Successfully connected to " << addr_str << ":" << port);

              #ifdef _WIN32
                unsigned long mode = 0;
                ioctlsocket(sock, FIONBIO, &mode);
              #else
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
              #endif
                        
              for (size_t j = 0; j < sockets.size(); ++j) {
                if (j != i) closesocket(sockets[j]);
              }
                        
              this->socket_fd_ = sock;
              this->connected_ = true;
              this->last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
                        
              freeaddrinfo(result);
              return true;

            } else {
              pockethttp_error("[SocketWrapper] Socket connection failed with error: " << error);
              closesocket(sock);
              sockets.erase(sockets.begin() + i);
              addresses.erase(addresses.begin() + i);
              --i;
            }
          }
        }
      }
        
      for (SOCKET sock : sockets) {
        closesocket(sock);
      }
    }

    pockethttp_error("[SocketWrapper] Failed to connect to " << host << ":" << port);
    freeaddrinfo(result);
    return false;
  }

} // namespace pockethttp
