#define NOMINMAX
#include <algorithm>
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "pockethttp/Logs.hpp"
#include "pockethttp/Random.hpp"
#include "pockethttp/Sockets/SocketPool.hpp"
#include "pockethttp/Http.hpp"
#include "pockethttp/Buffer.hpp"
#include "pockethttp/Decompress.hpp"
#include <cstring>
#include <cctype>

#define POCKET_HTTP_MAX_ATTEMPTS 10
#define POCKET_HTTP_CHUNK_SIZE 16384 // 16kb
#define BOUNDARY_PREFIX "------------------PHTTP"

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
    size_t total_length = 2 + boundary.size() + 4; // For the final boundary and CRLF

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
        total_length += 2 + boundary.size() + 2 
                      + 38 + item.name.size() + 13 + item.filename.size() + 3 // Content-Disposition: form-data; name="<name>"; filename="<filename>"\r\n
                      + 14 + item.content_type.size() + 2                     // Content-Type: <content_type>\r\n
                      + 2                                                     // \r\n
                      + item.content_length + 2;                              // <data>\r\n
      } else {
        // field
        total_length += 2 + boundary.size() + 2 
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
    pockethttp::FormDataItemState form_data_state;
    form_data_state.item = it;

    RequestCallback body_callback = [&req, &boundary, &useTransferChunked, &form_data_state](unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read) -> bool {
      
      switch (form_data_state.state) {
        case pockethttp::FormDataItemStateEnum::FORMDATA_HEADER: {
          pockethttp_log("[Http] Sending form-data header for item: " << form_data_state.item->name);
          // Create header if not created yet
          if (form_data_state.header == "") {
            form_data_state.header += "--" + boundary + "\r\n"
              + "Content-Disposition: form-data; name=\"" + form_data_state.item->name + "\"";

            if (form_data_state.item->value_callback != nullptr) { // file

              form_data_state.header += "; filename=\"" + form_data_state.item->filename + "\"\r\n"
                + "Content-Type: " + form_data_state.item->content_type + "\r\n\r\n";

            } else if (!form_data_state.item->value.empty()) { // field
              form_data_state.header += "\r\n\r\n";
            } else {
              pockethttp_error("[Http] FormDataItem must have either value or value_callback set");
              *read_data = pockethttp::Buffer::error;
              return false;
            }

            form_data_state.remaining = form_data_state.header.size();
          }
        
          // Send header
          size_t to_read = std::min(max_size, form_data_state.remaining);
          std::memcpy(data, form_data_state.header.c_str() + (form_data_state.header.size() - form_data_state.remaining), to_read);
          *read_data = to_read;

          if (to_read == form_data_state.remaining) {
            form_data_state.header = ""; // Clear header
            form_data_state.remaining = 0;
            form_data_state.total_sent = 0;
            form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_DATA; // Move to data state
          }

          return true;
        }

        case pockethttp::FormDataItemStateEnum::FORMDATA_DATA: {
          if (form_data_state.item->value_callback != nullptr) {
            pockethttp_log("[Http] Sending form-data file data for item: " << form_data_state.item->name);
            bool moreData = form_data_state.item->value_callback(
              data, 
              read_data, 
              max_size, 
              form_data_state.total_sent
            );

            form_data_state.total_sent += *read_data;

            if (!moreData) {
              form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_ENDING_CRLF;
              form_data_state.remaining = 2; // For the ending CRLF
            }

            return true;

          } else if (!form_data_state.item->value.empty()) { // field with value

            if (form_data_state.remaining == 0) {
              form_data_state.remaining = form_data_state.item->value.size();
            }

            size_t to_read = std::min(max_size, form_data_state.remaining);
            pockethttp_log("[Http] Sending " << to_read << " bytes of form-data field data for item: " << form_data_state.item->name);

            std::memcpy(data, form_data_state.item->value.c_str() + (form_data_state.item->value.size() - form_data_state.remaining), to_read);
            
            *read_data = to_read;
            form_data_state.remaining -= to_read;

            if (to_read == form_data_state.remaining || form_data_state.remaining == 0) {
              form_data_state.remaining = 2; // For the ending CRLF
              form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_ENDING_CRLF; // Move to ending CRLF state
            }

            return true;

          } else {
            pockethttp_error("[Http] FormDataItem must have either value or value_callback set");
            *read_data = pockethttp::Buffer::error;
            return false;
          }
        }

        case pockethttp::FormDataItemStateEnum::FORMDATA_ENDING_CRLF: {
          if (max_size < 2) {
            pockethttp_error("[Http] Buffer too small to write ending CRLF");
            *read_data = pockethttp::Buffer::error;
            return false;
          }

          pockethttp_log("[Http] Sending form-data ending CRLF for item: " << form_data_state.item->name);
          std::memcpy(data, "\r\n", 2);
          *read_data = 2;

          if (++form_data_state.item == req.form_data.end()) {
            form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_LAST_BOUNDARY;
            form_data_state.remaining = boundary.size() + 4; // For the final boundary and CRLF
          } else {
            form_data_state.state = pockethttp::FormDataItemStateEnum::FORMDATA_HEADER;
            form_data_state.remaining = 0;
          }

          return true; // More data to read
        }

        case pockethttp::FormDataItemStateEnum::FORMDATA_LAST_BOUNDARY: {
          pockethttp_log("[Http] Sending form-data last boundary");
          std::memcpy(data, ("--" + boundary + "--\r\n").c_str(), 2 + boundary.size() + 4);
          *read_data = 2 + boundary.size() + 4;
          return false; // No more data to read
        }

        default: {
          pockethttp_error("[Http] Unknown FormDataItemStateEnum state formatting form-data request body.");
          *read_data = pockethttp::Buffer::error;
          return false;
        }
      };

      return true; // More data to read
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
    size_t& buffer_data_size
  ) {
    pockethttp_log("[Http] Handling chunked transfer encoding");
    bool end_chunk = false;
    unsigned short attempts = 0; 
    size_t remaining_buffer_process = buffer_data_size; // The remmaining data in the buffer to format (remove chunk headers and CRLFs)
    size_t prev_chunk_data_offset = 0;

    ChunkedResponseState status;
    
    // Repeat format-pull until buffer is full or end of chunks
    do {

      unsigned char* buf = buffer + prev_chunk_data_offset;
      pockethttp_log("[Http] Starting to process " << remaining_buffer_process << " bytes in buffer. Status: " << status.status);
      
      // Remove chunk headers and CRLFs from the buffer
      while (remaining_buffer_process > 0) {
        switch (status.status) {
          case pockethttp::ChunkedStatus::CHUNKED_STATUS_HEX: {
            if (isdigit(*buf) || isalpha(*buf)) {
              pockethttp_log("[Http] Reading chunk size hex character: " << *buf);
              status.hexbuffer[status.hexindex++] = *buf;
              buf++;
              remaining_buffer_process--;
            
            } else {
              if (status.hexindex == 0) {
                pockethttp_error("[Http] Invalid chunk size format");
                return false;
              }

              status.hexbuffer[status.hexindex] = '\0';
              status.content_length = strtol(status.hexbuffer, nullptr, 16);
              status.remaining_content_length = status.content_length;
              status.hexindex = 0;

              if (status.content_length == 0) {
                status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_DONE;
                remaining_buffer_process = 0; // Stop processing
                break;
                pockethttp_log("[Http] Reached last chunk (size 0)");
              } else {
                status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_LF;
                pockethttp_log("[Http] New chunk of size: " << status.content_length);
              }

              // Move buffer pointer forward
              buf++;
              remaining_buffer_process--;
            }

            break;
          }

          case pockethttp::ChunkedStatus::CHUNKED_STATUS_LF: {
            if (*buf == 0x0A) {
              status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_DATA;
              pockethttp_log("[Http] CRLF after chunk size found");
              
              // Move buffer data to release chunk size
              std::memmove(
                buffer + prev_chunk_data_offset,
                ++buf,
                --remaining_buffer_process
              );

              buffer_data_size = prev_chunk_data_offset + remaining_buffer_process;
              buf = buffer + prev_chunk_data_offset;
              break;
            }

            buf++;
            remaining_buffer_process--;
            break;
          }

          case pockethttp::ChunkedStatus::CHUNKED_STATUS_DATA: {
            if (status.remaining_content_length <= remaining_buffer_process) {
              // Move buffer data pointer to release chunk data + CRLF
              buf += status.remaining_content_length;
              prev_chunk_data_offset += status.remaining_content_length;
              remaining_buffer_process -= status.remaining_content_length;

              status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_POSTLF;
              status.remaining_content_length = 0;
              pockethttp_log("[Http] Chunk data of size " << status.remaining_content_length << " processed");

            } else {
              status.remaining_content_length -= remaining_buffer_process;
              buf += remaining_buffer_process;
              pockethttp_log("[Http] Partial chunk data of size " << remaining_buffer_process << " processed");

              prev_chunk_data_offset += remaining_buffer_process;
              remaining_buffer_process = 0;
            }

            break;
          }

          case pockethttp::ChunkedStatus::CHUNKED_STATUS_POSTLF: {
            if (*buf == 0x0A) {
              status.status = pockethttp::ChunkedStatus::CHUNKED_STATUS_HEX;
              pockethttp_log("[Http] CRLF after chunk data found");
            }

            buf++;
            remaining_buffer_process--;
            break;
          }

          default: {
            pockethttp_error("[Http] Unknown error in chunked response handling");
            return false;
          }
        };
      };

      pockethttp_log("[Http] Buffer formatted, calling body callback with " << prev_chunk_data_offset << " bytes of data");
      size_t before_send_available = prev_chunk_data_offset;
      send_body_callback(buffer, prev_chunk_data_offset);
      pockethttp_log("[Http] Body callback finished. Remaining " << prev_chunk_data_offset << "/" << before_send_available << " bytes of data");

      if (prev_chunk_data_offset == 0 && status.status == pockethttp::ChunkedStatus::CHUNKED_STATUS_DONE) {
        end_chunk = true;
        pockethttp_log("[Http] All chunked data processed");
        break;
      }

      // Move remaining data to the beginning of the buffer
      std::memmove(
        buffer,
        buffer + (before_send_available - prev_chunk_data_offset),
        prev_chunk_data_offset
      );
      buffer_data_size = prev_chunk_data_offset + remaining_buffer_process;

      if (attempts > POCKET_HTTP_MAX_ATTEMPTS) {
        pockethttp_error("[Http] Too many attempts processing chunked data");
        return false;
      }

      if ((POCKET_HTTP_CHUNK_SIZE - buffer_data_size) == 0) {
        pockethttp_log("[Http] Buffer full after processing chunked data");
        attempts++;
        break; // Buffer full
      } else {
        attempts = 0; // Reset attempts if there is space in the buffer
      }

      // If not all transfer data was received
      if (status.status != pockethttp::ChunkedStatus::CHUNKED_STATUS_DONE) {
        // Pull more data if needed
        size_t pulled = socket->receive(
          buffer + buffer_data_size, 
          POCKET_HTTP_CHUNK_SIZE - buffer_data_size, 
          this->timeout_
        );

        pockethttp_log("[Http] Pulled " << pulled << " bytes from socket");
        remaining_buffer_process += pulled;
        buffer_data_size += pulled;
      }

    } while (!end_chunk);

    pockethttp_log("[Http] Finished processing chunked data (" << buffer_data_size << "). End chunk (bool): " << end_chunk);
    return end_chunk;
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
      if (!status && read_data == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Body callback error");
        socket->disconnect();
        return false;
      }

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
    std::string encoding = response.headers.get("Content-Encoding");
    std::shared_ptr<pockethttp::Decompressor> decompressorPtr = nullptr;
    std::function<void(unsigned char* buffer, size_t& size)> send_body_callback;

    if (encoding == "gzip" || encoding == "deflate") {
      pockethttp_log("[Http] Parsing compressed body: " << encoding);

      // Handle compression algorithm
      pockethttp::DecompressionAlgorithm algorithm = pockethttp::DecompressionAlgorithm::NONE;
      if (encoding == "gzip") {
        algorithm = pockethttp::DecompressionAlgorithm::GZIP;
      
      } else if (encoding == "deflate") {
        algorithm = pockethttp::DecompressionAlgorithm::DEFLATE;
      }

      // Initialize decompressor
      decompressorPtr = std::make_shared<pockethttp::Decompressor>(algorithm);
      pockethttp::DecompressionState state = decompressorPtr->init();
      if (state == pockethttp::DecompressionState::DECOMPRESS_ERROR) {
        socket->disconnect();
        return false;
      }

      // Define decompression callback
      send_body_callback = [decompressorPtr, &state, &response](unsigned char* buffer, size_t& size) {
        pockethttp_log("[Http] Decompressing body data (http-request lambda): " << size << " bytes.");

        // Handle decompression and send result to user's response callback
        state = decompressorPtr->decompress(buffer, size, response.body_callback);

        // size keeps the original value
        if (state == pockethttp::DecompressionState::DECOMPRESS_ERROR) return;

        if (state == pockethttp::DecompressionState::DECOMPRESSING) {
          size = decompressorPtr->getPendingInputSize();
          return;
        }

        size = 0;
      };

    } else {
      pockethttp_log("[Http] Parsing uncompressed body");

      send_body_callback = [&response](unsigned char* buffer, size_t& size) {
        response.body_callback((const unsigned char*)buffer, (const size_t&)size);
        size = 0;
      };
    }

    if (response.headers.get("Transfer-Encoding") != "chunked" && !response.headers.has("Content-Length")) {
      if (response.version == "HTTP/1.1") return true; // In 1.1 this means no body
    }

    // Handle transfer-encoding: chunked
    if (response.headers.get("Transfer-Encoding") == "chunked") {
      return this->handleChunked(response, socket, send_body_callback, buffer, read_data);
    }

    bool isHttp10 = (response.version == "HTTP/1.0");
    bool isConnClose = (response.headers.get("Connection") == "close");
    bool hasContentLength = response.headers.has("Content-Length");

    size_t content_length = hasContentLength ? std::stoi(response.headers.get("Content-Length")) : 0;
    pockethttp_log("[Http] Total body size: " << content_length << "; Read: " << read_data);

    total_read = read_data;
    size_t pulled = 0;
    size_t prev_send = 0;

    do {
      if ((total_read < content_length) || !hasContentLength) {
        // Pull data
        pulled = socket->receive(buffer + read_data, POCKET_HTTP_CHUNK_SIZE - read_data, this->timeout_);
        if (pulled == pockethttp::Buffer::error) {
          pockethttp_error("[Http] Failed to receive body data.");
          socket->disconnect();
          return (isHttp10 || isConnClose) && !hasContentLength;
        }

        read_data += pulled;
        total_read += pulled;
      }

      prev_send = read_data; // Data in buffer before sending (callback updates read_data with remaining data)
      send_body_callback(buffer, read_data);
      if (read_data == pockethttp::Buffer::error) {
        pockethttp_error("[Http] Failed to handle body's response callback.");
        socket->disconnect();
        return false;
      }

      if (read_data > 0) {
        // Move remaining data to the beginning of the buffer
        std::memmove(buffer, buffer + (prev_send - read_data), read_data);
      }

      if (hasContentLength && total_read >= content_length) break;

    } while (true);

    return true;
  }

} // namespace pockethttp