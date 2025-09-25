# pocket-http
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http?ref=badge_shield)


A lightweight, cross-platform HTTP/HTTPS client library for C++17 in an ultra-compact package.

## 🚀 Key Features

- **Zero Dependencies**: Compiles with a single command without linking any external libraries.
- **Cross-Platform**: Works seamlessly on Linux, macOS, and Windows.
- **HTTP/HTTPS Support**: Built-in TLS support via embedded [`BearSSL`](https://bearssl.org/).
- **Memory Efficient**: Chunked streaming keeps memory usage low and constant.
- **Automatic Compression**: Built-in Gzip and Deflate decompression via [`miniz`](https://github.com/richgel999/miniz).
- **Smart Socket Pooling**: Automatic connection reuse with intelligent cleanup.
- **Production Ready**: Timeout handling, connection management, and error recovery.

## 📦 What's Included

### Core Components

- **HTTP Client**: Full HTTP/1.1 implementation with chunked transfer encoding.
- **TLS Support**: Secure HTTPS connections via embedded [`BearSSL`](https://bearssl.org/).
- **Socket Pool**: Automatic connection reuse with timestamp-based cleanup.
- **Decompression**: Automatic Gzip/Deflate handling via [`miniz`](https://github.com/richgel999/miniz).
- **Headers Management**: Complete HTTP headers parsing and manipulation.

### Embedded Libraries

- [**`BearSSL`**](https://bearssl.org/): Lightweight TLS implementation (no OpenSSL dependency).
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
```

Then, if you want to use `HTTPS` with `BearSSL` you can privide your own `certs.hpp` file on `include/pockethttp/TLS/certs.hpp`. The default one is created from the [`Mozilla CA Certificates`](https://curl.se/docs/caextract.html).

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

You can see simple examples in [`examples/`](./examples/):

> [!IMPORTANT]  
> The `buildzri.config.json` file is configured to use the amalgamated version by default, to use the separated version replace `dist/*.cpp` under the `source.*` with `src/*.cpp`.

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

- `USE_POCKET_HTTP_BEARSSL`: Enable HTTPS support (recommended). WIthout this flag the TLSSocket wont be registered in SocketPool, so you can register your own implementation for HTTPS using a `SocketWrapper`.
- `USE_POCKET_HTTP_LOG`: Enable detailed information logging for debugging (only `std::cout`).
- `USE_POCKET_HTTP_ERR`: Enable detailed error logging for debugging (only `std::cerr`).
- `USE_POCKET_HTTP_MOZILLA_ROOT_CERTS`: Enable Mozilla Root Certificates for HTTPS.

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
- miniz: MIT from [richgel999/miniz](https://github.com/richgel999/miniz). 
Copyright 2013-2014 RAD Game Tools and Valve Software. Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC.
- bearssl: MIT from [bearssl.org](https://bearssl.org/). 
Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>.
- base64: Base64 encoder/decoder library: MIT from [tobiaslocker/base64](). Copyright (c) 2019 Tobias Locker.

---

**pocket-http** - When you need HTTP/HTTPS that just works, everywhere, with zero hassle.


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FIsmaCortGtz%2Fpocket-http?ref=badge_large)