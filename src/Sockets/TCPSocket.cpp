#include "pockethttp/Buffer.hpp"
#include "pockethttp/Sockets/TCPSocket.hpp"
#include "pockethttp/Sockets/SocketWrapper.hpp"
#include "pockethttp/Timestamp.hpp"
#include "pockethttp/Logs.hpp"
#include <string>
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <chrono>

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

  TCPSocket::TCPSocket() : socket_fd_(INVALID_SOCKET), connected_(false) {
    pockethttp_log("[TCPSocket] TCPSocket constructor called");
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
        pockethttp_error("[TCPSocket] WinSock not initialized, throwing exception");
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  TCPSocket::~TCPSocket() {
    pockethttp_log("[TCPSocket] TCPSocket destructor called");
    this->disconnect();
  }


  bool TCPSocket::connect(const std::string &host, int port) {
    pockethttp_log("[TCPSocket] Attempting to connect to " << host << ":" << port);

    if (connected_ || socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TCPSocket] Socket already connected, disconnecting first");
      disconnect();
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
      pockethttp_error("[TCPSocket] Failed to resolve hostname: " << host);
      return false;
    }

    pockethttp_log("[TCPSocket] Hostname resolved successfully");
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
      "[TCPSocket] Found " << ipv4_addresses.size() << " IPv4 addresses and " 
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

      pockethttp_log("[TCPSocket] Attempting parallel connection to " << addresses.size() << " addresses");

      for (auto addr_ptr : addresses) {
        SOCKET sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
        
        if (sock == INVALID_SOCKET) {
          pockethttp_error("[TCPSocket] Failed to create socket");
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
              pockethttp_error("[TCPSocket] Connect failed with error: " << error);
              closesocket(sock);
              continue;
            }
          #else
            if (errno != EINPROGRESS) {
              pockethttp_error("[TCPSocket] Connect failed: " << strerror(errno));
              closesocket(sock);
              continue;
            }
          #endif
        }
            
        sockets.push_back(sock);
      }
        
      if (sockets.empty()) {
        pockethttp_error("[TCPSocket] No sockets created for this batch");
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
          pockethttp_error("[TCPSocket] Select failed during connection");
          break;
        }
        if (select_result == 0) {
          pockethttp_log("[TCPSocket] Connection timeout");
          break;
        }
            
        for (size_t i = 0; i < sockets.size(); ++i) {
          SOCKET sock = sockets[i];
                
          if (FD_ISSET(sock, &error_fds)) {
            pockethttp_error("[TCPSocket] Socket error detected");
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
              pockethttp_log("[TCPSocket] Successfully connected to " << addr_str << ":" << port);

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
              pockethttp_error("[TCPSocket] Socket connection failed with error: " << error);
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

    pockethttp_error("[TCPSocket] Failed to connect to " << host << ":" << port);
    freeaddrinfo(result);
    return false;
  }

  void TCPSocket::disconnect() {
    if (this->socket_fd_ != INVALID_SOCKET) {
      pockethttp_log("[TCPSocket] Disconnecting socket");
      closesocket(this->socket_fd_);
      this->socket_fd_ = INVALID_SOCKET;
      this->connected_ = false;
    }
  }


  size_t TCPSocket::send(const unsigned char* buffer, const size_t size) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TCPSocket] Cannot send data: socket not connected");
      return pockethttp::Buffer::error;
    }

    pockethttp_log("[TCPSocket] Sending " << size << " bytes");
    size_t total_sent = 0;
    
    while (total_sent < size) {
      ssize_t bytes_sent = ::send(this->socket_fd_, buffer + total_sent, size - total_sent, 0);
      if (bytes_sent == SOCKET_ERROR || bytes_sent < 0) {
        #ifdef _WIN32
          pockethttp_error("[TCPSocket] Send failed with error: " << WSAGetLastError());
        #else
          pockethttp_error("[TCPSocket] Send failed with error: " << strerror(errno));
        #endif
        return pockethttp::Buffer::error;
      }
        
      total_sent += bytes_sent;
      pockethttp_log("[TCPSocket] Sent " << bytes_sent << " bytes. (" << total_sent << "/" << size << ")");
    }
    
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    pockethttp_log("[TCPSocket] Data sent successfully");
    return total_sent;
  }

  size_t TCPSocket::receive(unsigned char* buffer, size_t size, const int64_t& timeout) {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TCPSocket] Cannot receive data: socket not connected");
      return pockethttp::Buffer::error;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(this->socket_fd_, &read_fds);

    // Espera un corto periodo de tiempo para ver si hay datos.
    // Esto evita el bloqueo indefinido.
    struct timeval timeout_;
    timeout_.tv_sec = 0; // 0s
    timeout_.tv_usec = timeout * 1000; // Xms (default 30000ms [30s])

    int select_result = select(this->socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout_);
    pockethttp_log("[TCPSocket] Select result: " << select_result);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        pockethttp_error("[TCPSocket] Select failed with error: " << WSAGetLastError());
      #else
        pockethttp_error("[TCPSocket] Select failed with error: " << strerror(errno));
      #endif

      this->disconnect();
      return pockethttp::Buffer::error;
    }

    if (select_result == 0 || !FD_ISSET(this->socket_fd_, &read_fds)) {
      // Timeout o no hay datos, devuelve un vector vacío.
      pockethttp_error("[TCPSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = ::recv(this->socket_fd_, buffer, size, 0);
    pockethttp_log("[TCPSocket] Received " << bytes_received << " bytes");

    if (bytes_received == SOCKET_ERROR) {
      #ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
          pockethttp_error("[TCPSocket] Receive failed with error: " << err);
          this->disconnect();
        }
      #else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          pockethttp_error("[TCPSocket] Receive failed with error: " << strerror(errno));
          this->disconnect();
        }
      #endif
      return pockethttp::Buffer::error;
    }

    if (bytes_received == 0) {
      pockethttp_error("[TCPSocket] Server closed the connection: (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    return bytes_received;
  }


  bool TCPSocket::isConnected() {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_log("[TCPSocket] Socket is not connected");
      return false;
    }
    
    fd_set read_fds, write_fds, error_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_ZERO(&error_fds);
    FD_SET(socket_fd_, &read_fds);
    FD_SET(socket_fd_, &write_fds);
    FD_SET(socket_fd_, &error_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int result = select(this->socket_fd_ + 1, &read_fds, &write_fds, &error_fds, &timeout);
    if (result < 0) {
      pockethttp_error("[TCPSocket] Select failed in isConnected check");
      this->connected_ = false;
      this->socket_fd_ = INVALID_SOCKET;
      return false;
    }
    
    if (FD_ISSET(this->socket_fd_, &error_fds)) {
      pockethttp_error("[TCPSocket] Socket error detected in isConnected check");
      this->connected_ = false;
      this->socket_fd_ = INVALID_SOCKET;
      return false;
    }

    if (FD_ISSET(this->socket_fd_, &read_fds)) {
      char test_buffer[1];  
      #ifdef _WIN32
        int peek_result = ::recv(this->socket_fd_, test_buffer, 1, MSG_PEEK);
      #else
        int peek_result = ::recv(this->socket_fd_, test_buffer, 1, MSG_PEEK | MSG_DONTWAIT);
      #endif
        
      if (peek_result == 0) {
        pockethttp_log("[TCPSocket] Connection closed by peer");
        this->connected_ = false;
        this->socket_fd_ = INVALID_SOCKET;
        return false;
      }
        
      if (peek_result == SOCKET_ERROR) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error != WSAEWOULDBLOCK && error != WSAENOTSOCK) {
            pockethttp_error("[TCPSocket] Peek operation failed with error: " << error);
            this->connected_ = false;
            this->socket_fd_ = INVALID_SOCKET;
            return false;
          }
        #else
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            pockethttp_error("[TCPSocket] Peek operation failed: " << strerror(errno));
            this->connected_ = false;
            this->socket_fd_ = INVALID_SOCKET;
            return false;
          }
        #endif
      }
    }
    
    pockethttp_log("[TCPSocket] Socket connection is healthy");
    return true;
  }

  size_t TCPSocket::getAvailableOutBytes() const {
    if (!this->connected_ || this->socket_fd_ == INVALID_SOCKET) {
      pockethttp_error("[TCPSocket] Cannot get available bytes: socket not connected");
      return 0;
    }

    #ifdef _WIN32
      DWORD dwBytes;
      if (ioctlsocket(this->socket_fd_, FIONREAD, &dwBytes) != 0) {
        pockethttp_error("[TCPSocket] ioctlsocket failed: " << WSAGetLastError());
        return 0;
      } else {
        return static_cast<size_t>(dwBytes);
      }
    #else
      int pending = 0;
      if (ioctl(this->socket_fd_, FIONREAD, &pending) != 0) {
        pockethttp_error("[TCPSocket] ioctl failed: " << strerror(errno));
        return 0;
      } else {
        return static_cast<size_t>(pending);
      }
    #endif

    return 0;
  }

  int64_t TCPSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp