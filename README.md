# pocket-http
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http?ref=badge_shield)
![Cpp17](https://img.shields.io/badge/Made_for-C++17-blue)
![HTTP](https://img.shields.io/badge/Implements-HTTP-red)
![HTTPS](https://img.shields.io/badge/Implements-HTTPS-green)


A lightweight, cross-platform HTTP/HTTPS client library for C++17 in an ultra-compact package.

## 🚀 Key Features

- **Zero Dependencies**: Compiles with a single command without linking any external libraries.
- **Cross-Platform**: Works seamlessly on Linux, macOS, and Windows.
- **HTTP/HTTPS Support**: Built-in TLS support via embedded [`BearSSL`](https://bearssl.org/) or [`Mbed-TLS`](https://github.com/Mbed-TLS/mbedtls).
- **Memory Efficient**: Chunked streaming keeps memory usage low and constant.
- **Automatic Compression**: Built-in Gzip and Deflate decompression via [`miniz`](https://github.com/richgel999/miniz).
- **Smart Socket Pooling**: Automatic connection reuse with intelligent cleanup.
- **Production Ready**: Timeout handling, connection management, and error recovery.

## 📦 What's Included

### Core Components

- **HTTP Client**: Full HTTP/1.1 implementation with chunked transfer encoding.
- **TLS Support**: Secure HTTPS connections via embedded [`BearSSL`](https://bearssl.org/) or [`Mbed-TLS`](https://github.com/Mbed-TLS/mbedtls).
- **Socket Pool**: Automatic connection reuse with timestamp-based cleanup.
- **Decompression**: Automatic Gzip/Deflate handling via [`miniz`](https://github.com/richgel999/miniz).
- **Headers Management**: Complete HTTP headers parsing and manipulation.

### Embedded Libraries

- [**`BearSSL`**](https://bearssl.org/): Lightweight TLS implementation (no OpenSSL dependency).
- [**`Mbed-TLS`**](https://github.com/Mbed-TLS/mbedtls): TLS implementation.
- [**`miniz`**](https://github.com/richgel999/miniz): High-performance compression library.

## 🏗️ Architecture

### Memory Management

- **Streaming Architecture**: Processes data in chunks (`16KB`)
- **Constant Memory Usage**: Memory footprint remains stable regardless of response size.
- **Smart Buffering**: Automatic buffer sizing based on Content-Length and compression.

### Connection Management

- **Socket Pool**: Reuses connections for improved performance.
- **Automatic Cleanup**: Removes expired connections based on configurable timeout.
- **Connection State**: Tracks last usage timestamp for each socket.
- **Graceful Handling**: Detects and recovers from server-side disconnections.

## 🛠️ Building

First of all, you need to clone the repository.

```bash
git clone https://github.com/IsmaCortGtz/pocket-http.git

# If you want to use mbedtls you need to fetch submodules
git submodule update --init --recursive
```

Then, if you want to use `HTTPS` with `BearSSL` or `MbedTLS` you can privide your own `certs.hpp` file on `include/pockethttp/Sockets/certs.hpp`. The default one is created from the [`Mozilla CA Certificates`](https://curl.se/docs/caextract.html).

```bash
# This command will create the certs.hpp file

# cryptography library is needed, install it with 'pip install cryptography'

python scripts/parse.py cacert.pem
```

### Building

You can build with `CMake`, I recommend you to use `Ninja`, but you can use `Make` if you want to,

```bash
# Create build directory
mkdir build
cd build

# Build
cmake .. -G Ninja -DUSE_POCKET_HTTP_MBEDTLS=ON
ninja
```

## 📚 Usage

You can see simple examples in [`examples/`](./examples/):

- [basic_request.cpp](./examples/basic_request.cpp)
- [download.cpp](./examples/download.cpp)
- [form_data.cpp](./examples/form_data.cpp)
- [form_urlencoded.cpp](./examples/form_urlencoded.cpp)
- [send_file.cpp](./examples/send_file.cpp)
- [send_json.cpp](./examples/send_json.cpp)
- [systemcerts.cpp](./examples/systemcerts.cpp)

## 📋 API Reference

TODO

## 🔧 Configuration

### Compile-Time Options

- `USE_POCKET_HTTP_BEARSSL` (Default: `OFF`): Enable HTTPS support with `BearSSL`. Without this flag the TLSSocket wont be registered in SocketPool, so you can register your own implementation for HTTPS using a `SocketWrapper`.
- `USE_POCKET_HTTP_MBEDTLS` (Default: `OFF`): Enable HTTPS support with `MbedTLS` (recommended). Without this flag the `MbedTLSSocket` wont be registered in SocketPool, so you can register your own implementation for HTTPS using a `SocketWrapper`.
- `USE_POCKET_HTTP_LOG` (Default: `OFF`): Enable detailed information logging for debugging (only `std::cout`).
- `USE_POCKET_HTTP_ERR` (Default: `OFF`): Enable detailed error logging for debugging (only `std::cerr`).
- `USE_POCKET_HTTP_MOZILLA_ROOT_CERTS` (Default: `OFF`): Enable Mozilla Root Certificates for HTTPS.

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
- **TLS**: Optimized BearSSL and [`Mbed-TLS`](https://github.com/Mbed-TLS/mbedtls) provides fast HTTPS with small footprint

## 🤝 Contributing

This is a focused, production-ready library. Contributions should maintain the zero-dependency philosophy and cross-platform compatibility.

## 📜 License

- pocket-http: MIT. Copyright (c) 2025 Ismael Cortés Gutiérrez.
- miniz: MIT from [richgel999/miniz](https://github.com/richgel999/miniz). 
Copyright 2013-2014 RAD Game Tools and Valve Software. Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC.
- bearssl: MIT from [bearssl.org](https://bearssl.org/). 
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>.
- base64: Base64 encoder/decoder library: MIT from [tobiaslocker/base64](). Copyright (c) 2019 Tobias Locker.
- mbedTLS: [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) or [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) from [Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls). (Using [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html))

---

**pocket-http** - When you need HTTP/HTTPS that just works, everywhere, with zero hassle.


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http?ref=badge_large)