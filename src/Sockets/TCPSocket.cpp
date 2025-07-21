#include <pockethttp/Sockets/TCPSocket.hpp>
#include <pockethttp/Timestamp.hpp>
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
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] TCPSocket constructor called" << std::endl;
#endif
    #ifdef _WIN32
      auto& manager = WinSockManager::getInstance();
      if (!manager.isInitialized()) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TCPSocket] WinSock not initialized, throwing exception" << std::endl;
#endif
        throw std::runtime_error("WinSock initialization failed");
      }
    #endif
  }

  TCPSocket::~TCPSocket() {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] TCPSocket destructor called" << std::endl;
#endif
    disconnect();
  }

  bool TCPSocket::connect(const std::string &host, int port) {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Attempting to connect to " << host << ":" << port << std::endl;
#endif
    if (connected_ || socket_fd_ != INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TCPSocket] Socket already connected, disconnecting first" << std::endl;
#endif
        disconnect();
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
      std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
#ifdef POCKET_HTTP_LOGS
      std::cerr << "[PocketHttp::TCPSocket] Failed to resolve hostname: " << host << std::endl;
#endif
      return false;
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Hostname resolved successfully" << std::endl;
#endif
    
    std::vector<struct addrinfo*> ipv4_addresses;
    std::vector<struct addrinfo*> ipv6_addresses;
    
    for (struct addrinfo* addr_ptr = result; addr_ptr != nullptr; addr_ptr = addr_ptr->ai_next) {
      if (addr_ptr->ai_family == AF_INET) {
        ipv4_addresses.push_back(addr_ptr);
      } else if (addr_ptr->ai_family == AF_INET6) {
        ipv6_addresses.push_back(addr_ptr);
      }
    }

#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Found " << ipv4_addresses.size() << " IPv4 addresses and " 
              << ipv6_addresses.size() << " IPv6 addresses" << std::endl;
#endif

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
      
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] Attempting parallel connection to " << addresses.size() << " addresses" << std::endl;
#endif
      
      for (auto addr_ptr : addresses) {
        SOCKET sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
        if (sock == INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
          std::cerr << "[PocketHttp::TCPSocket] Failed to create socket" << std::endl;
#endif
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
#ifdef POCKET_HTTP_LOGS
              std::cerr << "[PocketHttp::TCPSocket] Connect failed with error: " << error << std::endl;
#endif
              closesocket(sock);
              continue;
            }
          #else
            if (errno != EINPROGRESS) {
#ifdef POCKET_HTTP_LOGS
              std::cerr << "[PocketHttp::TCPSocket] Connect failed: " << strerror(errno) << std::endl;
#endif
              closesocket(sock);
              continue;
            }
          #endif
        }
            
        sockets.push_back(sock);
      }
        
      if (sockets.empty()) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TCPSocket] No sockets created for this batch" << std::endl;
#endif
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
#ifdef POCKET_HTTP_LOGS
          std::cerr << "[PocketHttp::TCPSocket] Select failed during connection" << std::endl;
#endif
          break;
        }
        if (select_result == 0) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::TCPSocket] Connection timeout" << std::endl;
#endif
          break;
        }
            
        for (size_t i = 0; i < sockets.size(); ++i) {
          SOCKET sock = sockets[i];
                
          if (FD_ISSET(sock, &error_fds)) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::TCPSocket] Socket error detected" << std::endl;
#endif
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
              if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_len) == 0 && error == 0) {
            #else
              if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 && error == 0) {
            #endif
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
                        
#ifdef POCKET_HTTP_LOGS
                std::cout << "[PocketHttp::TCPSocket] Successfully connected to " << addr_str << ":" << port << std::endl;
#endif
                        
                #ifdef _WIN32
                  unsigned long mode = 0;
                  ioctlsocket(sock, FIONBIO, &mode);
                #else
                  int flags = fcntl(sock, F_GETFL, 0);
                  fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
                #endif
                        
                for (size_t j = 0; j < sockets.size(); ++j) {
                  if (j != i) {
                    closesocket(sockets[j]);
                  }
                }
                        
                socket_fd_ = sock;
                connected_ = true;
                last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
                        
                freeaddrinfo(result);
                return true;
              } else {
#ifdef POCKET_HTTP_LOGS
                std::cerr << "[PocketHttp::TCPSocket] Socket connection failed with error: " << error << std::endl;
#endif
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
    
#ifdef POCKET_HTTP_LOGS
    std::cerr << "[PocketHttp::TCPSocket] Failed to connect to " << host << ":" << port << std::endl;
#endif
    freeaddrinfo(result);
    return false;
  }

  void TCPSocket::disconnect() {
    if (socket_fd_ != INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] Disconnecting socket" << std::endl;
#endif
      closesocket(socket_fd_);
      socket_fd_ = INVALID_SOCKET;
      connected_ = false;
    }
  }

  bool TCPSocket::send(const std::vector<uint8_t> &data) {
    if (!connected_ || socket_fd_ == INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
      std::cerr << "[PocketHttp::TCPSocket] Cannot send data: socket not connected" << std::endl;
#endif
      return false;
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Sending " << data.size() << " bytes" << std::endl;
#endif
    
    const char* buffer = reinterpret_cast<const char*>(data.data());
    size_t total_sent = 0;
    size_t data_size = data.size();
    
    while (total_sent < data_size) {
      int bytes_sent = ::send(socket_fd_, buffer + total_sent, data_size - total_sent, 0);  
      if (bytes_sent == SOCKET_ERROR) {
        #ifdef _WIN32
          std::cerr << "Send failed: " << WSAGetLastError() << std::endl;
        #else
          std::cerr << "Send failed: " << strerror(errno) << std::endl;
        #endif
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TCPSocket] Send operation failed" << std::endl;
#endif
        return false;
      }
        
      total_sent += bytes_sent;
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] Sent " << bytes_sent << " bytes (" << total_sent << "/" << data_size << ")" << std::endl;
#endif
    }
    
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Data sent successfully" << std::endl;
#endif
    return true;
  }

std::vector<uint8_t> TCPSocket::receive() {
    constexpr size_t CHUNK_SIZE = 16384;
    if (!connected_ || socket_fd_ == INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
      std::cerr << "[PocketHttp::TCPSocket] Cannot receive data: socket not connected" << std::endl;
#endif
      return {};
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(socket_fd_, &read_fds);

    // Espera un corto periodo de tiempo para ver si hay datos.
    // Esto evita el bloqueo indefinido.
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000; // 100ms

    int select_result = select(socket_fd_ + 1, &read_fds, nullptr, nullptr, &timeout);

    if (select_result == SOCKET_ERROR) {
      #ifdef _WIN32
        std::cerr << "select() failed: " << WSAGetLastError() << std::endl;
      #else
        std::cerr << "select() failed: " << strerror(errno) << std::endl;
      #endif
#ifdef POCKET_HTTP_LOGS
      std::cerr << "[PocketHttp::TCPSocket] Select failed during receive operation" << std::endl;
#endif
      connected_ = false;
      return {};
    }

    if (select_result == 0 || !FD_ISSET(socket_fd_, &read_fds)) {
      // Timeout o no hay datos, devuelve un vector vacío.
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] No data available for reading (timeout or no data)" << std::endl;
#endif
      return {};
    }

    char buffer[CHUNK_SIZE];
    int bytes_received = ::recv(socket_fd_, buffer, sizeof(buffer), 0);

    if (bytes_received == SOCKET_ERROR) {
      #ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
          std::cerr << "Receive failed: " << err << std::endl;
#ifdef POCKET_HTTP_LOGS
          std::cerr << "[PocketHttp::TCPSocket] Receive operation failed with error: " << err << std::endl;
#endif
          connected_ = false;
        }
      #else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
          std::cerr << "Receive failed: " << strerror(errno) << std::endl;
#ifdef POCKET_HTTP_LOGS
          std::cerr << "[PocketHttp::TCPSocket] Receive operation failed: " << strerror(errno) << std::endl;
#endif
          connected_ = false;
        }
      #endif
      return {};
    }

    if (bytes_received == 0) {
      // El servidor cerró la conexión.
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] Server closed the connection" << std::endl;
#endif
      connected_ = false;
      return {};
    }

#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Received " << bytes_received << " bytes" << std::endl;
#endif
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    return std::vector<uint8_t>(buffer, buffer + bytes_received);
  }

  bool TCPSocket::isConnected() {
    if (!connected_ || socket_fd_ == INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] Socket is not connected" << std::endl;
#endif
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
    
    int result = select(socket_fd_ + 1, &read_fds, &write_fds, &error_fds, &timeout);
    if (result < 0) {
#ifdef POCKET_HTTP_LOGS
      std::cerr << "[PocketHttp::TCPSocket] Select failed in isConnected check" << std::endl;
#endif
      connected_ = false;
      return false;
    }
    
    if (FD_ISSET(socket_fd_, &error_fds)) {
#ifdef POCKET_HTTP_LOGS
      std::cout << "[PocketHttp::TCPSocket] Socket error detected in isConnected check" << std::endl;
#endif
      connected_ = false;
      return false;
    }
    
    if (FD_ISSET(socket_fd_, &read_fds)) {
      char test_buffer[1];  
      #ifdef _WIN32
        int peek_result = ::recv(socket_fd_, test_buffer, 1, MSG_PEEK);
      #else
        int peek_result = ::recv(socket_fd_, test_buffer, 1, MSG_PEEK | MSG_DONTWAIT);
      #endif
        
      if (peek_result == 0) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TCPSocket] Connection closed by peer" << std::endl;
#endif
        connected_ = false;
        return false;
      }
        
      if (peek_result == SOCKET_ERROR) {
        #ifdef _WIN32
          int error = WSAGetLastError();
          if (error != WSAEWOULDBLOCK && error != WSAENOTSOCK) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::TCPSocket] Peek operation failed with error: " << error << std::endl;
#endif
            connected_ = false;
            return false;
          }
        #else
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::TCPSocket] Peek operation failed: " << strerror(errno) << std::endl;
#endif
            connected_ = false;
            return false;
          }
        #endif
      }
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TCPSocket] Socket connection is healthy" << std::endl;
#endif
    return true;
  }

  int64_t TCPSocket::getTimestamp() const {
    return last_used_timestamp_;
  }

} // namespace pockethttp