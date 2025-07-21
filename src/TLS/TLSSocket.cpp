#ifdef POCKET_HTTP_USE_BEARSSL

#include <pockethttp/TLS/certs.hpp>
#include <pockethttp/TLS/TLSSocket.hpp>
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

// BearSSL I/O callback implementations
int TLSSocket::sock_read(void* ctx, unsigned char* buf, size_t len) {
    int* socket_fd = static_cast<int*>(ctx);
    
    for (;;) {
        #ifdef _WIN32
            int rlen = recv(*socket_fd, reinterpret_cast<char*>(buf), len, 0);
        #else
            ssize_t rlen = read(*socket_fd, buf, len);
        #endif
        
        if (rlen <= 0) {
            #ifdef _WIN32
                int error = WSAGetLastError();
                if (error == WSAEINTR) {
                    continue;
                }
            #else
                if (rlen < 0 && errno == EINTR) {
                    continue;
                }
            #endif
            return -1;
        }
        return static_cast<int>(rlen);
    }
}

int TLSSocket::sock_write(void* ctx, const unsigned char* buf, size_t len) {
    int* socket_fd = static_cast<int*>(ctx);
    
    for (;;) {
        #ifdef _WIN32
            int wlen = ::send(*socket_fd, reinterpret_cast<const char*>(buf), len, 0);
        #else
            ssize_t wlen = write(*socket_fd, buf, len);
        #endif
        
        if (wlen <= 0) {
            #ifdef _WIN32
                int error = WSAGetLastError();
                if (error == WSAEINTR) {
                    continue;
                }
            #else
                if (wlen < 0 && errno == EINTR) {
                    continue;
                }
            #endif
            return -1;
        }
        return static_cast<int>(wlen);
    }
}

TLSSocket::TLSSocket() 
    : socket_fd_(INVALID_SOCKET), 
      connected_(false), 
      last_used_timestamp_(0),
      ssl_client_(nullptr),
      x509_context_(nullptr),
      sslio_context_(nullptr),
      iobuf_(nullptr) {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] TLSSocket constructor called" << std::endl;
#endif
    
    #ifdef _WIN32
        auto& manager = WinSockManager::getInstance();
        if (!manager.isInitialized()) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::TLSSocket] WinSock not initialized, throwing exception" << std::endl;
#endif
            throw std::runtime_error("WinSock initialization failed");
        }
    #endif
}

TLSSocket::~TLSSocket() {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] TLSSocket destructor called" << std::endl;
#endif
    disconnect();
}

TLSSocket::TLSSocket(TLSSocket&& other) noexcept
    : socket_fd_(other.socket_fd_),
      connected_(other.connected_),
      last_used_timestamp_(other.last_used_timestamp_),
      ssl_client_(other.ssl_client_),
      x509_context_(other.x509_context_),
      sslio_context_(other.sslio_context_),
      iobuf_(other.iobuf_) {
    
    other.socket_fd_ = INVALID_SOCKET;
    other.connected_ = false;
    other.last_used_timestamp_ = 0;
    other.ssl_client_ = nullptr;
    other.x509_context_ = nullptr;
    other.sslio_context_ = nullptr;
    other.iobuf_ = nullptr;
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] TLSSocket moved" << std::endl;
#endif
}

TLSSocket& TLSSocket::operator=(TLSSocket&& other) noexcept {
    if (this != &other) {
        disconnect();
        
        socket_fd_ = other.socket_fd_;
        connected_ = other.connected_;
        last_used_timestamp_ = other.last_used_timestamp_;
        ssl_client_ = other.ssl_client_;
        x509_context_ = other.x509_context_;
        sslio_context_ = other.sslio_context_;
        iobuf_ = other.iobuf_;
        
        other.socket_fd_ = INVALID_SOCKET;
        other.connected_ = false;
        other.last_used_timestamp_ = 0;
        other.ssl_client_ = nullptr;
        other.x509_context_ = nullptr;
        other.sslio_context_ = nullptr;
        other.iobuf_ = nullptr;
        
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] TLSSocket move assigned" << std::endl;
#endif
    }
    return *this;
}

bool TLSSocket::initializeTLS(const std::string& hostname) {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Initializing TLS for hostname: " << hostname << std::endl;
#endif
    
    try {
        // Allocate contexts using malloc instead of new
        ssl_client_ = static_cast<br_ssl_client_context*>(malloc(sizeof(br_ssl_client_context)));
        x509_context_ = static_cast<br_x509_minimal_context*>(malloc(sizeof(br_x509_minimal_context)));
        sslio_context_ = static_cast<br_sslio_context*>(malloc(sizeof(br_sslio_context)));
        
        if (!ssl_client_ || !x509_context_ || !sslio_context_) {
            throw std::runtime_error("Failed to allocate TLS contexts");
        }
        
        // Allocate I/O buffer
        iobuf_ = static_cast<unsigned char*>(malloc(BR_SSL_BUFSIZE_BIDI));
        if (!iobuf_) {
            throw std::runtime_error("Failed to allocate I/O buffer");
        }
        
        // Initialize the client context with full profile and X.509 validation
        br_ssl_client_init_full(ssl_client_, x509_context_, TAs, TAs_NUM);
        
        // Set the I/O buffer
        br_ssl_engine_set_buffer(&ssl_client_->eng, iobuf_, BR_SSL_BUFSIZE_BIDI, 1);
        
        // Reset the client context for new handshake
        br_ssl_client_reset(ssl_client_, hostname.c_str(), 0);
        
        // Initialize the simplified I/O wrapper context
        br_sslio_init(sslio_context_, &ssl_client_->eng, sock_read, &socket_fd_, sock_write, &socket_fd_);
        
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] TLS initialization successful" << std::endl;
#endif
        return true;
        
    } catch (const std::exception& e) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] TLS initialization failed: " << e.what() << std::endl;
#endif
        cleanupTLS();
        return false;
    }
}

void TLSSocket::cleanupTLS() {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Cleaning up TLS resources" << std::endl;
#endif
    
    if (sslio_context_) {
        free(sslio_context_);
        sslio_context_ = nullptr;
    }
    
    if (ssl_client_) {
        free(ssl_client_);
        ssl_client_ = nullptr;
    }
    
    if (x509_context_) {
        free(x509_context_);
        x509_context_ = nullptr;
    }
    
    if (iobuf_) {
        free(iobuf_);
        iobuf_ = nullptr;
    }
}

int TLSSocket::createTCPConnection(const std::string& host, int port) {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Creating TCP connection to " << host << ":" << port << std::endl;
#endif
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    std::string port_str = std::to_string(port);
    int status = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (status != 0) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] getaddrinfo error: " << gai_strerror(status) << std::endl;
#endif
        return INVALID_SOCKET;
    }
    
    int fd = INVALID_SOCKET;
    for (struct addrinfo* addr_ptr = result; addr_ptr != nullptr; addr_ptr = addr_ptr->ai_next) {
        fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, addr_ptr->ai_protocol);
        if (fd == INVALID_SOCKET) {
            continue;
        }
        
        if (::connect(fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == 0) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::TLSSocket] TCP connection established" << std::endl;
#endif
            break;
        }
        
        closesocket(fd);
        fd = INVALID_SOCKET;
    }
    
    freeaddrinfo(result);
    return fd;
}

bool TLSSocket::performTLSHandshake(const std::string& hostname) {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Performing TLS handshake" << std::endl;
#endif
    
    // Force handshake by attempting to flush
    if (br_sslio_flush(sslio_context_) < 0) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] TLS handshake failed during flush" << std::endl;
#endif
        return false;
    }
    
    // Check final state
    unsigned state = br_ssl_engine_current_state(&ssl_client_->eng);
    if (state == BR_SSL_CLOSED) {
        int err = br_ssl_engine_last_error(&ssl_client_->eng);
        if (err != 0) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::TLSSocket] TLS handshake failed with SSL error: " << err << std::endl;
#endif
            return false;
        }
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] TLS handshake completed" << std::endl;
#endif
    return true;
}

bool TLSSocket::connect(const std::string& host, int port) {
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Attempting to connect to " << host << ":" << port << std::endl;
#endif
    
    if (connected_ || socket_fd_ != INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] Socket already connected, disconnecting first" << std::endl;
#endif
        disconnect();
    }
    
    // Create TCP connection
    socket_fd_ = createTCPConnection(host, port);
    if (socket_fd_ == INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] Failed to create TCP connection" << std::endl;
#endif
        return false;
    }
    
    // Initialize TLS
    if (!initializeTLS(host)) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] Failed to initialize TLS" << std::endl;
#endif
        closesocket(socket_fd_);
        socket_fd_ = INVALID_SOCKET;
        return false;
    }
    
    // Perform TLS handshake
    if (!performTLSHandshake(host)) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] TLS handshake failed" << std::endl;
#endif
        cleanupTLS();
        closesocket(socket_fd_);
        socket_fd_ = INVALID_SOCKET;
        return false;
    }
    
    connected_ = true;
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Successfully connected to " << host << ":" << port << std::endl;
#endif
    return true;
}

void TLSSocket::disconnect() {
    if (socket_fd_ != INVALID_SOCKET) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] Disconnecting socket" << std::endl;
#endif
        
        // Properly close SSL connection if connected
        if (connected_ && sslio_context_) {
            // Try to send close_notify alert
            br_sslio_close(sslio_context_);
        }
        
        cleanupTLS();
        closesocket(socket_fd_);
        socket_fd_ = INVALID_SOCKET;
        connected_ = false;
    }
}

bool TLSSocket::send(const std::vector<uint8_t>& data) {
    if (!connected_ || socket_fd_ == INVALID_SOCKET || !sslio_context_) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] Cannot send data: socket not connected" << std::endl;
#endif
        return false;
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Sending " << data.size() << " bytes" << std::endl;
#endif
    
    // Send data using br_sslio_write_all for complete transmission
    int result = br_sslio_write_all(sslio_context_, data.data(), data.size());
    
    if (result < 0) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] SSL write failed" << std::endl;
#endif
        return false;
    }
    
    // Flush the SSL buffer
    if (br_sslio_flush(sslio_context_) < 0) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] SSL flush failed" << std::endl;
#endif
        return false;
    }
    
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Data sent successfully" << std::endl;
#endif
    return true;
}

std::vector<uint8_t> TLSSocket::receive() {
    constexpr size_t CHUNK_SIZE = 16384;
    if (!connected_ || socket_fd_ == INVALID_SOCKET || !sslio_context_) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] Cannot receive data: socket not connected" << std::endl;
#endif
        return {};
    }
    
    unsigned char buffer[CHUNK_SIZE];
    int bytes_received = br_sslio_read(sslio_context_, buffer, sizeof(buffer));
    
    if (bytes_received < 0) {
        // Check if it's a SSL error or just no data available
        unsigned state = br_ssl_engine_current_state(&ssl_client_->eng);
        if (state == BR_SSL_CLOSED) {
            int err = br_ssl_engine_last_error(&ssl_client_->eng);
            if (err != 0) {
#ifdef POCKET_HTTP_LOGS
                std::cerr << "[PocketHttp::TLSSocket] SSL error during receive: " << err << std::endl;
#endif
                connected_ = false;
            } else {
#ifdef POCKET_HTTP_LOGS
                std::cout << "[PocketHttp::TLSSocket] SSL connection closed cleanly" << std::endl;
#endif
                connected_ = false;
            }
        }
        return {};
    }
    
    if (bytes_received == 0) {
        // No data available or connection closed
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] No data available or connection closed" << std::endl;
#endif
        return {};
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] Received " << bytes_received << " bytes" << std::endl;
#endif
    last_used_timestamp_ = pockethttp::Timestamp::getCurrentTimestamp();
    return std::vector<uint8_t>(buffer, buffer + bytes_received);
}

bool TLSSocket::isConnected() {
    if (!connected_ || socket_fd_ == INVALID_SOCKET || !sslio_context_) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] Socket is not connected" << std::endl;
#endif
        return false;
    }
    
    // Check SSL engine state
    unsigned state = br_ssl_engine_current_state(&ssl_client_->eng);
    
    if (state == BR_SSL_CLOSED) {
        int err = br_ssl_engine_last_error(&ssl_client_->eng);
        if (err != 0) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::TLSSocket] SSL connection closed with error: " << err << std::endl;
#endif
            connected_ = false;
            return false;
        }
    }
    
    // Check underlying TCP connection
    fd_set read_fds, error_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&error_fds);
    FD_SET(socket_fd_, &read_fds);
    FD_SET(socket_fd_, &error_fds);
    
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    
    int result = select(socket_fd_ + 1, &read_fds, nullptr, &error_fds, &timeout);
    if (result < 0) {
#ifdef POCKET_HTTP_LOGS
        std::cerr << "[PocketHttp::TLSSocket] Select failed in isConnected check" << std::endl;
#endif
        connected_ = false;
        return false;
    }
    
    if (FD_ISSET(socket_fd_, &error_fds)) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::TLSSocket] Socket error detected in isConnected check" << std::endl;
#endif
        connected_ = false;
        return false;
    }
    
#ifdef POCKET_HTTP_LOGS
    std::cout << "[PocketHttp::TLSSocket] TLS socket connection is healthy" << std::endl;
#endif
    return true;
}

int64_t TLSSocket::getTimestamp() const {
    return last_used_timestamp_;
}

} // namespace pockethttp

#endif // POCKET_HTTP_USE_BEARSSL