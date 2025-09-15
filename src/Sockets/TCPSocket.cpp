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
    typedef SSIZE_T ssize_t;
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

  TCPSocket::TCPSocket() {
    this->connected_ = false;
    this->socket_fd_ = INVALID_SOCKET;
    
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
    return this->openTCPSocket(host, port);
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
      ssize_t bytes_sent = ::send(this->socket_fd_, (const char *)(buffer + total_sent), size - total_sent, 0);
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

    // Wait a short time period to see if there is data.
    // This avoids blocking indefinitely.
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
      // No data or timeout, return Buffer error.
      pockethttp_error("[TCPSocket] No data available for reading (timeout [" << timeout << "] or no data): (" << errno << ") " << strerror(errno));
      this->disconnect();
      return pockethttp::Buffer::error;
    }

    ssize_t bytes_received = ::recv(this->socket_fd_, (char *)buffer, size, 0);
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

  int64_t TCPSocket::getTimestamp() const {
    return this->last_used_timestamp_;
  }

} // namespace pockethttp