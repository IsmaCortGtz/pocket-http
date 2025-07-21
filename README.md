# pocket-http

A lightweight, cross-platform HTTP/HTTPS client library for C++17+ in an ultra-compact package.

## 🚀 Key Features

- **Zero Dependencies**: Compiles with a single command without linking any external libraries
- **Cross-Platform**: Works seamlessly on Linux, macOS, and Windows
- **HTTP/HTTPS Support**: Built-in TLS support via embedded [`BearSSL`](https://bearssl.org/)
- **Memory Efficient**: Chunked streaming keeps memory usage low and constant
- **Automatic Compression**: Built-in Gzip and Deflate decompression via [`miniz`](https://github.com/richgel999/miniz)
- **Smart Socket Pooling**: Automatic connection reuse with intelligent cleanup
- **Production Ready**: Timeout handling, connection management, and error recovery

## 📦 What's Included

### Core Components

- **HTTP Client**: Full HTTP/1.1 implementation with chunked transfer encoding
- **TLS Support**: Secure HTTPS connections via embedded [`BearSSL`](https://bearssl.org/)
- **Socket Pool**: Automatic connection reuse with timestamp-based cleanup
- **Decompression**: Automatic Gzip/Deflate handling via [`miniz`](https://github.com/richgel999/miniz)
- **Headers Management**: Complete HTTP headers parsing and manipulation

### Embedded Libraries

- [**`BearSSL`**](https://bearssl.org/): Lightweight TLS implementation (no OpenSSL dependency)
- [**`miniz`**](https://github.com/richgel999/miniz): High-performance compression library

## 🏗️ Architecture

### Memory Management

- **Streaming Architecture**: Processes data in chunks (16KB)
- **Constant Memory Usage**: Memory footprint remains stable regardless of response size
- **Smart Buffering**: Automatic buffer sizing based on Content-Length and compression

### Connection Management

- **Socket Pool**: Reuses connections for improved performance
- **Automatic Cleanup**: Removes expired connections based on configurable timeout
- **Connection State**: Tracks last usage timestamp for each socket
- **Graceful Handling**: Detects and recovers from server-side disconnections

## 🛠️ Building

First of all, you need to clone the repository.

```bash
git clone https://github.com/IsmaCortGtz/pocket-http.git
```

Then, if you want to use `HTTPS` with `BearSSL` you need to privide a `certs.hpp` file on `include/pockethttp/TLS/certs.hpp`. You can create it from the [`Mozilla CA Certificates`](https://curl.se/docs/caextract.html).

```bash
# This command will create the certs.hpp file

# cryptography library is needed, install it with 'pip install cryptography'

python scripts/parse.py cacert.pem
```

### Single Command Build

```bash
# Using buildzri (recommended)
python scripts/bz.py
```

> [!IMPORTANT]  
> You can build by your own using `g++`, `cl` or any `C++17` compiler. But you need care about including every cpp and c file as in the `buildzri.config.json`, and obviusly, you need to include the same header paths.

## 📚 Usage

### Basic Usage

```cpp
#include <pockethttp/pockethttp.hpp>
#include <iostream>

int main() {
    pockethttp::Http client;
    
    // Create a request
    pockethttp::Request request;
    request.method = "GET";
    request.url = "https://api.example.com/data";
    request.headers.set("User-Agent", "PocketHTTP/1.0");
    
    // Make the request with streaming callback
    pockethttp::Response response;
    std::string body;
    
    client.request(request, [&](const pockethttp::Response& res, const std::vector<uint8_t>& chunk) {
        if (body.empty()) {
            response = res; // Capture headers on first chunk
            
            // Pre-allocate based on Content-Length if available
            std::string contentLength = res.headers.get("Content-Length");
            if (!contentLength.empty()) {
                body.reserve(std::stoul(contentLength));
            }
        }
        
        // Append chunk data
        body.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return true; // Continue receiving
    });
    
    std::cout << "Status: " << response.status << std::endl;
    std::cout << "Body: " << body << std::endl;
    
    return 0;
}
```

### POST with JSON Body

```cpp
pockethttp::Http client;
pockethttp::Request request;

request.method = "POST";
request.url = "https://api.example.com/users";
request.headers.set("Content-Type", "application/json");
request.headers.set("Accept", "application/json");

// Set JSON body
std::string jsonData = R"({"name": "John", "email": "john@example.com"})";
request.body.assign(jsonData.begin(), jsonData.end());

client.request(request, [](const pockethttp::Response& res, const std::vector<uint8_t>& chunk) {
    // Handle response...
    return true;
});
```

### Custom Headers and Timeout

```cpp
pockethttp::Http client(60000); // 60 second timeout

pockethttp::Request request;
request.method = "GET";
request.url = "https://api.example.com/slow-endpoint";
request.headers.set("Authorization", "Bearer your-token");
request.headers.set("Accept", "application/json");
request.headers.set("Accept-Encoding", "gzip, deflate"); // Automatic decompression

client.request(request, callback);
```

## 📋 API Reference

### `pockethttp::Http`

#### Constructor

```cpp
Http(int64_t timeout = 30000); // timeout in milliseconds
```

#### Methods

```cpp
void request(const Request& req, 
            std::function<bool(const Response&, const std::vector<uint8_t>&)> callback);
```

### `pockethttp::Request`

```cpp
struct Request {
    std::string version = "HTTP/1.1"; // HTTP version
    std::string method;               // HTTP method (GET, POST, etc.)
    std::string url;                  // Full URL including protocol
    Headers headers;                  // HTTP headers
    std::vector<uint8_t> body;       // Request body
};
```

### `pockethttp::Response`

```cpp
struct Response {
    std::string version;    // HTTP version from server
    uint16_t status;        // HTTP status code
    std::string statusText; // HTTP status text
    Headers headers;        // Response headers
    std::vector<uint8_t> body; // Response body (for reference)
};
```

### `pockethttp::Headers`

```cpp
class Headers {
public:
    void set(const std::string& name, const std::string& value);
    std::string get(const std::string& name) const;
    bool has(const std::string& name) const;
    std::string dump() const; // Get all headers as string
};
```

## 🔧 Configuration

### Compile-Time Options

- `POCKET_HTTP_USE_BEARSSL`: Enable HTTPS support (recommended). WIthout this flag the TLSSocket wont be registered in SocketPool, so you can register your own implementation for HTTPS using a `SocketWrapper`.
- `POCKET_HTTP_LOGS`: Enable detailed logging for debugging

## 🎯 Use Cases

Perfect for:

- **Embedded Systems**: Minimal memory footprint and zero dependencies
- **Microservices**: Lightweight HTTP client for service communication  
- **IoT Applications**: Efficient HTTPS communication for resource-constrained devices
- **Standalone Tools**: No dependency hell, single-file distribution
- **Cross-Platform Apps**: Write once, compile anywhere
- **Performance-Critical Applications**: Streaming architecture prevents memory spikes

## 🔄 How It Works

### Streaming Architecture

1. **Request Sending**: Large payloads sent in 16KB chunks
2. **Response Receiving**: Data processed as it arrives, never buffering entire response
3. **Memory Management**: Constant memory usage regardless of payload size
4. **Compression**: Automatic detection and decompression of Gzip/Deflate content

### Socket Pool Management

1. **Pool Creation**: Maintains pool of reusable connections per host:port
2. **Usage Tracking**: Each socket tagged with last activity timestamp
3. **Automatic Cleanup**: Expired connections removed based on timeout
4. **Failure Recovery**: Detects closed connections and creates new ones

## 📊 Performance

- **Memory**: Constant ~64KB maximum usage regardless of response size
- **Speed**: Connection reuse eliminates handshake overhead  
- **Compression**: Automatic decompression with minimal memory overhead
- **TLS**: Optimized BearSSL provides fast HTTPS with small footprint

## 🤝 Contributing

This is a focused, production-ready library. Contributions should maintain the zero-dependency philosophy and cross-platform compatibility.

## 📜 License

- pocket-http: MIT. Copyright (c) 2025 Ismael Cortés Gutiérrez.
- miniz: MIT from [richgel999/miniz](https://github.com/richgel999/miniz). Copyright 2013-2014 RAD Game Tools and Valve Software. Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC
- bearssl: MIT from [bearssl.org](https://bearssl.org/). Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

---

**pocket-http** - When you need HTTP/HTTPS that just works, everywhere, with zero hassle.
