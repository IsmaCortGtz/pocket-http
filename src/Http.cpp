#include "pockethttp/Logs.hpp"
#include "pockethttp/Random.hpp"
#include "pockethttp/Sockets/SocketPool.hpp"
#include "pockethttp/Sockets/TCPSocket.hpp"
#include "pockethttp/Http.hpp"
#include "pockethttp/Buffer.hpp"
#include "pockethttp/Decompress.hpp"
#include <cstring>

#define POCKET_HTTP_CHUNK_SIZE 16384 // 16kb
#define BOUNDARY_PREFIX "------------------PHTTP-"

namespace pockethttp {

  Http::Http() : timeout_(30000) {}
  Http::Http(int64_t timeout) : timeout_(timeout) {}
  Http::~Http() {}

  bool Http::request(pockethttp::Request& req, pockethttp::Response& res) {
    pockethttp::Remote remote = pockethttp::utils::parseUrl(req.url);

    if (!req.headers.has("Content-Length")) {
      if (req.body_callback == nullptr && !req.body.empty()) {
        req.headers.set("Content-Length", std::to_string(req.body.size()));
      } else if (req.body_callback != nullptr && req.body.empty()) {
        req.headers.set("Transfer-Encoding", "chunked");
      }
    }

    RequestCallback body_callback = [&req](unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read) -> bool {  
      if (req.body_callback == nullptr) {
        if (req.body.empty()) {
          pockethttp_log("[Http] No body to send");
          *read_data = 0; // No body to read
          return false; // No more data to read
        } else {
          size_t to_read = std::min(max_size, req.body.size() - total_read);
          if (to_read > 0) {
            std::memcpy(data, req.body.data() + total_read, to_read);
            *read_data = to_read;
            return true; // More data to read
          } else {
            *read_data = 0; // No more data to read
            return false; // No more data to read
          }
        }
      } else {
        // Custom body callback
        return req.body_callback(data, read_data, max_size, total_read);
      }
    };

    return request(remote, req.method, req.headers, res, body_callback);
  }

  bool Http::request(pockethttp::FormDataRequest& req, pockethttp::Response& res) {
    pockethttp::Remote remote = pockethttp::utils::parseUrl(req.url);
    std::string boundary = this->generateBoundary();
    size_t total_length = boundary.size() + 4; // For the final boundary and CRLF

    req.headers.set("Content-Type", "multipart/form-data; boundary=" + boundary);
    if (req.headers.has("Content-Length")) {
      req.headers.remove("Content-Length");
      pockethttp_log("[Http] Removed Content-Length header for FormDataRequest");
    }

    bool useTransferChunked = false;
    for (auto item : req.form_data) {
      if (item.value_callback != nullptr) {
        if (item.content_length == pockethttp::Buffer::error) {
          useTransferChunked = true;
          break;
        }

        if (item.filename.empty() || item.content_type.empty()) {
          pockethttp_error("FormDataItem with value_callback must have filename and content_type set");
          return false;
        }

        // file
        total_length += boundary.size() + 2 
                      + 38 + item.name.size() + 13 + item.filename.size() + 3 // Content-Disposition: form-data; name="<name>"; filename="<filename>"\r\n
                      + 14 + item.name.size() + 2                             // Content-Type: <content_type>\r\n
                      + 2                                                     // \r\n
                      + item.content_length + 2;                              // <data>\r\n
      } else {
        // field
        total_length += boundary.size() + 2 
                      + 38 + item.name.size() + 3 // Content-Disposition: form-data; name="<name>"\r\n
                      + 2                         // \r\n
                      + item.value.size() + 2;    // <data>\r\n
      }
    }

    if (!useTransferChunked && total_length > 0) {
      req.headers.set("Content-Length", std::to_string(total_length));
    } else {
      useTransferChunked = true;
      req.headers.set("Transfer-Encoding", "chunked");
    }

    std::vector<FormDataItem>::iterator it = req.form_data.begin();

    RequestCallback body_callback = [&req, &useTransferChunked, &it](unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read) -> bool {
      
      // Temporal
      *read_data = 0;
      return false;
      
      if (it == req.form_data.end()) {
        // last boundary
      }
      
      // Format form-data using chunks
      if (it->value_callback != nullptr) {
        // file
        
        it++;
      } else if (!it->value.empty()) {
        // field
        
        
      } else {
        *read_data = 0;
        return false;
      }
    };

    return request(remote, req.method, req.headers, res, body_callback);
  }

  /* Private Methods */

  void Http::setDefaultHeaders(Headers& headers, Remote& remote) {
    pockethttp_log("[Http] Setting default headers for host: " << remote.host);
    if (!headers.has("Accept")) {
      headers.set("Accept", "*/*");
    }
    if (!headers.has("Host")) {
      headers.set("Host", remote.host);
    }
    if (!headers.has("Connection")) {
      headers.set("Connection", "keep-alive");
    }
    if (!headers.has("User-Agent")) {
      headers.set("User-Agent", "PocketHTTP/1.0");
    }
    if (!headers.has("Accept-Encoding")) {
      headers.set("Accept-Encoding", "gzip, deflate");
    }
  }

  std::string Http::generateBoundary() {
    return BOUNDARY_PREFIX + pockethttp::random::generateRandomString(22);
  }

  size_t Http::parseStatusLine(pockethttp::Response& response, std::shared_ptr<SocketWrapper> socket, unsigned char* buffer, const size_t& buffer_size, size_t& total_bytes_read) {
    pockethttp_log("[Http] Parsing status line from socket");

    bool status_line = false;
    total_bytes_read = 0;

    while (total_bytes_read < POCKET_HTTP_CHUNK_SIZE && !status_line) {
      // Pull data from socket until CRLF is found
      size_t n = socket->receive(buffer + total_bytes_read, buffer_size - total_bytes_read, this->timeout_);
      if (n == pockethttp::Buffer::error) return pockethttp::Buffer::error;
      pockethttp_log("[Http] Received " << n << " bytes from socket.");
      if (n == 0) continue;
      total_bytes_read += n;

      // Find end of status line
      size_t end_line = pockethttp::Buffer::find(buffer, total_bytes_read, (const unsigned char*)"\r\n", 2);
      if (end_line == pockethttp::Buffer::error) return pockethttp::Buffer::error; // Continue if end of line not pulled yet

      // Parse HTTP version
      size_t offset = 0, length = 0;
      length = pockethttp::Buffer::find(buffer, total_bytes_read, (const unsigned char*)" ", 1);
      if (length == pockethttp::Buffer::error) return pockethttp::Buffer::error;
      response.version = std::string(reinterpret_cast<const char*>(buffer), length);
      offset += length + 1;

      // Parse status code
      length = pockethttp::Buffer::find(buffer + offset, total_bytes_read - offset, (const unsigned char*)" ", 1);
      if ((length + offset) == pockethttp::Buffer::error || (length + offset) > end_line) length = end_line - offset; // If no space found, assume rest is status code

      response.status = 0;
      for (size_t i = offset; i < offset + length; i++) {
        response.status = response.status * 10 + (buffer[i] - '0'); 
      }
      offset += length + 1;
    
      // Parse status text
      if (offset < end_line) {
        response.statusText = std::string(reinterpret_cast<const char*>(buffer + offset), end_line - offset);
        offset += end_line + 2; // Skip CRLF
      }

      // Move remaining data to the beginning of the buffer
      std::memmove(buffer, buffer + end_line + 2, total_bytes_read - (end_line + 2));
      total_bytes_read -= (end_line + 2);
      pockethttp_log("[Http] Moved remaining " << total_bytes_read << " bytes to the beginning of the buffer.");
      status_line = true;
      break;
    }

    if (!status_line) return pockethttp::Buffer::error;
    return total_bytes_read;
  }

  size_t Http::parseHeaders(pockethttp::Response& response, std::shared_ptr<SocketWrapper> socket, unsigned char* buffer, const size_t& buffer_size, size_t& total_bytes_read) {
    pockethttp_log("[Http] Parsing headers from socket");
    bool end_header = false;

    do {
      // Pull data from socket until CRLF is found
      size_t end_headers_pos = pockethttp::Buffer::find(buffer, total_bytes_read, (const unsigned char*)"\r\n\r\n", 4);
      
      // Keep pulling data
      if (end_headers_pos == pockethttp::Buffer::error) {
        size_t n = socket->receive(buffer + total_bytes_read, buffer_size - total_bytes_read, this->timeout_);
        if (n == pockethttp::Buffer::error) return pockethttp::Buffer::error;
        if (n == 0) continue;
        pockethttp_log("[Http] Received " << n << " bytes from socket.");
        total_bytes_read += n;
      }

      // Parse headers
      response.headers.load(std::string(reinterpret_cast<const char*>(buffer), end_headers_pos));
      end_header = true;

      // Move any body data to the beginning of the buffer
      std::memmove(buffer, buffer + end_headers_pos + 4, total_bytes_read - (end_headers_pos + 4));
      total_bytes_read -= (end_headers_pos + 4);
      pockethttp_log("[Http] Moved remaining " << total_bytes_read << " bytes to the beginning of the buffer.");

    } while(total_bytes_read < POCKET_HTTP_CHUNK_SIZE && !end_header);

    if (!end_header) return pockethttp::Buffer::error;
    return total_bytes_read;

  }

  bool Http::handleChunked(
    pockethttp::Response& response,
    std::shared_ptr<SocketWrapper> socket,
    std::function<void(unsigned char* buffer, size_t& size)> send_body_callback,
    unsigned char* buffer,
    const size_t buffer_size,
    size_t& prev_data_size
  ) {
    pockethttp_log("[Http] Handling chunked transfer encoding. Buffer size: " << buffer_size);
    bool end_chunk = false;
    bool current_header = true; // Is waiting for chunk header

    size_t current_chunk_size = 0, prev_send_size = 0, to_send_size = 0;

    do {
      // Pull data from socket until CRLF is found
      size_t end_line = pockethttp::Buffer::find(buffer, prev_data_size, (const unsigned char*)"\r\n", 2);
      
      if (current_header) {
        // Keep pulling data
        if (end_line == pockethttp::Buffer::error) {
          size_t n = socket->receive(buffer + prev_data_size, buffer_size - prev_data_size, this->timeout_);
          if (n == pockethttp::Buffer::error) return false;
          if (n == 0) continue;
          pockethttp_log("[Http] Received " << n << " bytes from socket in chunk header.");
          prev_data_size += n;
        }

        // Handle chunk size
        for (size_t i = 0; i < end_line; i++) {
          unsigned char c = buffer[i];
          unsigned val = 0;

          if (c >= '0' && c <= '9') val = c - '0';
          else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
          else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');

          current_chunk_size = (current_chunk_size << 4) | val;
        }

        if (current_chunk_size == 0) return true; // End of chunks

        // Move any body data to the beginning of the buffer
        pockethttp_log("[Http] Current chunk size: " << current_chunk_size << ".");
        std::memmove(buffer, buffer + end_line + 2, prev_data_size - (end_line + 2));
        prev_data_size -= (end_line + 2);
        current_header = false;
        continue;
      }

      // Handle pull
      if (prev_data_size <= 0) {
        size_t n = socket->receive(buffer + prev_data_size, buffer_size - prev_data_size, this->timeout_);
        if (n == pockethttp::Buffer::error) return false;
        if (n == 0) continue;
        pockethttp_log("[Http] Received " << n << " bytes of " << buffer_size << " from socket in chunk body. (Total: " << prev_data_size + n << ")");
        prev_data_size += n;

        end_line = pockethttp::Buffer::find(buffer, prev_data_size, (const unsigned char*)"\r\n", 2);
        pockethttp_log("[Http] Re-evaluated end line position: " << end_line << "/" << prev_data_size << (end_line == pockethttp::Buffer::error ? " (Not Found)" : ""));
      }

      if (buffer_size != POCKET_HTTP_CHUNK_SIZE || buffer_size < 10) {
        pockethttp_log("[Http] Buffer size is not valid for chunked transfer.");
        return false;
      }

      // Handle body data

      prev_send_size = prev_data_size;
      to_send_size = prev_data_size;

      if (end_line != pockethttp::Buffer::error) {
        prev_send_size = end_line;
        to_send_size = end_line;
      }

      pockethttp_log("[Http] Preparing to send " << to_send_size << " bytes of chunked body data. Previous data size: " << prev_data_size << ". Previous send size: " << prev_send_size << ". End line: " << end_line);
      send_body_callback(buffer, to_send_size);

      pockethttp_log("[Http] Remaining " << to_send_size << " bytes of chunked body data. Error? " << (to_send_size == pockethttp::Buffer::error) << " End line? " << (end_line == pockethttp::Buffer::error));

      if (to_send_size <= 0 && end_line != pockethttp::Buffer::error) {
        // Move any remaining data to the beginning of the buffer
        std::memmove(buffer, buffer + end_line + 2, prev_data_size - (end_line + 2));
        prev_data_size -= (end_line + 2);
        current_chunk_size = 0;
        current_header = true;
        
      } else {
        // Move any remaining data to the beginning of the buffer
        if (prev_data_size - (prev_send_size - to_send_size) > 0) std::memmove(buffer, buffer + to_send_size, prev_data_size - (prev_send_size - to_send_size));
        prev_data_size -= (prev_send_size - to_send_size);
      }

    } while(prev_data_size < POCKET_HTTP_CHUNK_SIZE && !end_chunk);

    if (!end_chunk) return false;
    return true;
  }

  bool Http::request(
    pockethttp::Remote& remote,
    std::string& method,
    pockethttp::Headers& headers,
    pockethttp::Response& response,
    RequestCallback& body_callback
  ) {
    // Get socket
    pockethttp_log("[Http] Making request: " << method << " " << remote.path);
    std::shared_ptr<SocketWrapper> socket = SocketPool::getSocket(remote.protocol, remote.host, remote.port);
    if (!socket || socket == nullptr) {
      pockethttp_error("[Http] Failed to get socket: nullptr");
      return false;
    }

    // Set default headers
    this->setDefaultHeaders(headers, remote);

    // Send headers
    std::string request_str = method + " " + remote.path + " HTTP/1.1\r\n" + headers.dump() + "\r\n";
    pockethttp_log("[Http] Sending request headers.");

    size_t res = socket->send(reinterpret_cast<const unsigned char*>(request_str.c_str()), request_str.size());
    if (res == pockethttp::Buffer::error) {
      pockethttp_error("[Http] Failed to send request: " << request_str);
      socket->disconnect();
      return false;
    }

    // Free request_str memory
    request_str.clear(); // Empties the string
    request_str.shrink_to_fit(); // Reduces capacity to fit size (empty string)

    // Send body (if there is no body the callback will return empty and false)
    unsigned char buffer[POCKET_HTTP_CHUNK_SIZE];
    size_t read_data = 0;
    size_t total_read = 0;

    while(true) {
      read_data = 0;
      bool status = body_callback(buffer, &read_data, POCKET_HTTP_CHUNK_SIZE, total_read);
      if (!status && read_data == 0) break;
      if (read_data == 0) continue;

      if (headers.get("Transfer-Encoding") == "chunked") {
        pockethttp_log("[Http] Sending chunked body data of size: " << read_data);
        // Send chunked transfer encoding (size as hex + CRLF)
        std::ostringstream chunk_size_ss;
        chunk_size_ss << std::hex << read_data << "\r\n";

        // Append at the beginning of the buffer
        std::memmove(buffer + chunk_size_ss.str().size(), buffer, read_data);
        std::memcpy(buffer, chunk_size_ss.str().c_str(), chunk_size_ss.str().size());

        // Append CRLF at the end
        std::memcpy(buffer + chunk_size_ss.str().size() + read_data, "\r\n", 2);
        read_data += chunk_size_ss.str().size() + 2;
      }

      size_t res = socket->send(buffer, read_data);
      if (res == pockethttp::Buffer::error || res != read_data) {
        pockethttp_error("[Http] Failed to send body data. Sent " << total_read << " of " << read_data << " bytes.");
        socket->disconnect();
        return false;
      }

      if (read_data > 0) total_read += read_data;
      if (!status) break;
    }

    if (headers.get("Transfer-Encoding") == "chunked") {
      if (socket->send(reinterpret_cast<const unsigned char*>("0\r\n\r\n"), 5) == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Failed to send chunked transfer encoding footer");
        socket->disconnect();
        return false;
      }
    }

    // Parse Status line
    read_data = 0;
    read_data = this->parseStatusLine(response, socket, buffer, POCKET_HTTP_CHUNK_SIZE, read_data);
    if (read_data == pockethttp::Buffer::error) {
      pockethttp_error("[Http] Failed to parse status line");
      socket->disconnect();
      return false;
    }

    // Parse headers
    read_data = this->parseHeaders(response, socket, buffer, POCKET_HTTP_CHUNK_SIZE, read_data);
    if (read_data == pockethttp::Buffer::error) {
      pockethttp_error("[Http] Failed to parse headers");
      socket->disconnect();
      return false;
    }

    // Parse body
    pockethttp_log("[Http] Starting body parse");
    std::function<void(unsigned char* buffer, size_t& size)> send_body_callback;

    std::string encoding = response.headers.get("Content-Encoding");
    std::shared_ptr<pockethttp::Decompressor> decompressorPtr = nullptr;
    if (encoding == "gzip" || encoding == "deflate") {
      pockethttp_log("[Http] Parsing compressed body: " << encoding);

      // Handle compress
      pockethttp::DecompressionAlgorithm algo = pockethttp::DecompressionAlgorithm::NONE;

      if (encoding == "gzip") algo = pockethttp::DecompressionAlgorithm::GZIP;
      else if (encoding == "deflate") algo = pockethttp::DecompressionAlgorithm::DEFLATE;

      decompressorPtr = std::make_shared<pockethttp::Decompressor>(algo);
      pockethttp::DecompressionState state = decompressorPtr->init();
      if (state == pockethttp::DecompressionState::ERROR) {
        socket->disconnect();
        return false;
      }

      send_body_callback = [decompressorPtr, &state, &response](unsigned char* buffer, size_t& size) {
        pockethttp_log("[Http] Decompressing body data (http-request lambda): " << size << " bytes.");
        state = decompressorPtr->decompress(buffer, size, response.body_callback);
        pockethttp_log("[Http] Decompression state: " << (state == pockethttp::DecompressionState::DECOMPRESSING ? "DECOMPRESSING" : state == pockethttp::DecompressionState::FINISHED ? "FINISHED" : state == pockethttp::DecompressionState::ERROR ? "ERROR" : "UNKNOWN"));

        if (state == pockethttp::DecompressionState::ERROR) {
          size = pockethttp::Buffer::error;
          return;
        }

        if (state == pockethttp::DecompressionState::DECOMPRESSING) {
          size_t pending = decompressorPtr->getPendingInputSize();
          if (pending > 0) {
            pockethttp_log("[Http] Decompressor has pending input size: " << pending);
            size = pending;
            return;
          }
        }

        size = 0;
      };

    } else {
      pockethttp_log("[Http] Parsing uncompressed body");
      send_body_callback = response.body_callback;
    }

    if (response.headers.get("Transfer-Encoding") != "chunked" && !response.headers.has("Content-Length")) {
      if (response.version == "HTTP/1.1") return true; // In 1.1 this means no body
    }

    // Handle transfer-encoding: chunked
    if (response.headers.get("Transfer-Encoding") == "chunked") {
      return this->handleChunked(response, socket, send_body_callback, buffer, POCKET_HTTP_CHUNK_SIZE, read_data);
    }

    // If is HTTP/1.0 is valid to close connection after send all data.
    bool isV10 = (response.version == "HTTP/1.0");
    // If is HTTP/1.1 is valid to close connection if Connection: close is set.
    bool isClose = (response.headers.get("Connection") == "close");


    total_read = read_data;
    size_t pulled = 0, prev_send = 0;
    bool hasContentLength = response.headers.has("Content-Length");
    size_t content_length = hasContentLength ? std::stoi(response.headers.get("Content-Length")) : 0;

    pockethttp_log("[Http] Total body size: " << content_length << "; Read: " << read_data);

    do {
      if ((hasContentLength && total_read < content_length) || !hasContentLength) {
        // Pull data
        pulled = socket->receive(buffer + read_data, POCKET_HTTP_CHUNK_SIZE - read_data, this->timeout_);
        if (pulled == pockethttp::Buffer::error) {
          pockethttp_error("[Http] Failed to receive body data");
          socket->disconnect();
          return (isV10 || isClose) && !hasContentLength;
        }

        read_data += pulled;
        total_read += pulled;
      }

      prev_send = read_data; // Data in buffer before sending (user should update read_data with remaining data)
      send_body_callback(buffer, read_data);
      if (read_data == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Failed to handle response body (user's callback or decompressor)");
        socket->disconnect();
        return false;
      }

      if (read_data > 0) {
        // Move remaining data to the beginning of the buffer
        std::memmove(buffer, buffer + read_data, prev_send - read_data);
      }

      if (total_read >= content_length && hasContentLength) break;

    } while (true);

    return true;
  }

} // namespace pockethttp