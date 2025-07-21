#ifndef POCKET_HTTP_HTTP_HPP
#define POCKET_HTTP_HTTP_HPP

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <pockethttp/Decompress.hpp>
#include <pockethttp/Headers.hpp>
#include <pockethttp/Request.hpp>
#include <pockethttp/Response.hpp>
#include <pockethttp/Timestamp.hpp>
#include <pockethttp/Sockets/SocketWrapper.hpp>
#include <pockethttp/Sockets/SocketPool.hpp>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#ifdef POCKET_HTTP_LOGS
#include <iostream>
#endif

namespace pockethttp {

  class Http {
    private:
      static constexpr int64_t DEFAULT_TIMEOUT = 30000;
      static constexpr int MAX_RECEIVE_ATTEMPTS = 100;
      static constexpr int MIN_ATTEMPTS_NO_CONTENT_LENGTH = 5;
      static constexpr int RECEIVE_DELAY_MS = 50;
      static constexpr size_t SEND_CHUNK_SIZE = 16384; // 16KB chunks for sending requests
      static constexpr size_t MAX_TOTAL_BUFFER_SIZE = 65536; // 64KB absolute maximum memory usage
      static constexpr size_t PARSE_BUFFER_SIZE = 32768; // 32KB for parsing chunks
      static constexpr size_t COMPRESSION_BUFFER_SIZE = 32768; // 32KB for compression data
      static constexpr size_t PROCESS_THRESHOLD = 16384; // Process when buffer reaches 16KB

      int64_t timeout_;

      enum class CompressionType { NONE, GZIP, DEFLATE };

      void setDefaultHeaders(Request& request, const std::string& host) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] setDefaultHeaders: setting default "
                     "headers for host "
                  << host << "\n";
#endif
        if (!request.headers.has("Host")) {
          request.headers.set("Host", host);
        }
        if (!request.headers.has("Connection")) {
          request.headers.set("Connection", "keep-alive");
        }
        if (!request.headers.has("User-Agent")) {
          request.headers.set("User-Agent", "PocketHTTP/1.0");
        }
        if (!request.headers.has("Accept-Encoding")) {
          request.headers.set("Accept-Encoding", "gzip, deflate");
        }

        // Set Content-Length if body is present and not already set
        if (!request.body.empty() && !request.headers.has("Content-Length")) {
          request.headers.set(
              "Content-Length", std::to_string(request.body.size()));
        }
      }

      void setDefaultHeadersForStreaming(
          Request& request, const std::string& host, size_t contentLength = 0) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] setDefaultHeadersForStreaming: "
                     "setting default headers for host "
                  << host << "\n";
#endif
        if (!request.headers.has("Host")) {
          request.headers.set("Host", host);
        }
        if (!request.headers.has("Connection")) {
          request.headers.set("Connection", "keep-alive");
        }
        if (!request.headers.has("User-Agent")) {
          request.headers.set("User-Agent", "PocketHTTP/1.0");
        }
        if (!request.headers.has("Accept-Encoding")) {
          request.headers.set("Accept-Encoding", "gzip, deflate");
        }

        // For streaming, set appropriate transfer encoding
        if (contentLength > 0) {
          request.headers.set("Content-Length", std::to_string(contentLength));
        } else if (!request.headers.has("Content-Length") &&
                   !request.headers.has("Transfer-Encoding")) {
          request.headers.set("Transfer-Encoding", "chunked");
        }
      }

      bool sendHttpRequestInChunks(std::shared_ptr<pockethttp::SocketWrapper> socket,
          const Request& request, const std::string& path) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] sendHttpRequestInChunks: method="
                  << request.method << ", path=" << path
                  << ", version=" << request.version << "\n";
#endif

        // Build HTTP request headers
        std::string httpRequest =
            request.method + " " + path + " " + request.version + "\r\n";
        httpRequest += request.headers.dump() + "\r\n";

        // Convert headers to vector for uniform handling
        std::vector<uint8_t> headerData(httpRequest.begin(), httpRequest.end());

#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::Http] sendHttpRequestInChunks: sending headers ("
            << headerData.size() << " bytes)\n";
#endif

        // Send headers first
        if (!sendDataInChunks(socket, headerData)) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] sendHttpRequestInChunks: failed to "
                       "send headers\n";
#endif
          return false;
        }

        // Send body if present
        if (!request.body.empty()) {
#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Http] sendHttpRequestInChunks: sending body ("
              << request.body.size() << " bytes)\n";
#endif
          if (!sendDataInChunks(socket, request.body)) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] sendHttpRequestInChunks: failed "
                         "to send body\n";
#endif
            return false;
          }
        }

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] sendHttpRequestInChunks: request sent "
                     "successfully\n";
#endif
        return true;
      }

      bool sendDataInChunks(std::shared_ptr<pockethttp::SocketWrapper> socket,
          const std::vector<uint8_t>& data) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] sendDataInChunks: sending "
                  << data.size() << " bytes in chunks of " << SEND_CHUNK_SIZE
                  << "\n";
#endif

        size_t totalSent = 0;

        while (totalSent < data.size()) {
          size_t chunkSize = std::min(SEND_CHUNK_SIZE, data.size() - totalSent);

          std::vector<uint8_t> chunk(
              data.begin() + totalSent, data.begin() + totalSent + chunkSize);

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] sendDataInChunks: sending chunk "
                    << (totalSent / SEND_CHUNK_SIZE + 1)
                    << ", size=" << chunkSize << ", progress=" << totalSent
                    << "/" << data.size() << "\n";
#endif

          if (!socket->send(chunk)) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] sendDataInChunks: failed to send "
                         "chunk at offset "
                      << totalSent << "\n";
#endif
            return false;
          }

          totalSent += chunkSize;
        }

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] sendDataInChunks: all " << totalSent
                  << " bytes sent successfully\n";
#endif
        return true;
      }

      bool sendHttpRequestHeaders(std::shared_ptr<pockethttp::SocketWrapper> socket,
          const Request& request, const std::string& path) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] sendHttpRequestHeaders: method="
                  << request.method << ", path=" << path
                  << ", version=" << request.version << "\n";
#endif

        std::string httpRequest =
            request.method + " " + path + " " + request.version + "\r\n";
        httpRequest += request.headers.dump() + "\r\n";

        std::vector<uint8_t> headerData(httpRequest.begin(), httpRequest.end());

#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::Http] sendHttpRequestHeaders: sending headers ("
            << headerData.size() << " bytes)\n";
#endif

        return socket->send(headerData);
      }

      bool sendDataStream(std::shared_ptr<pockethttp::SocketWrapper> socket,
          std::function<std::vector<uint8_t>()> dataProvider) {
#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::Http] sendDataStream: starting streaming upload\n";
#endif

        size_t totalSent = 0;

        while (true) {
          std::vector<uint8_t> chunk = dataProvider();

          if (chunk.empty()) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] sendDataStream: stream completed, "
                         "total sent="
                      << totalSent << " bytes\n";
#endif
            break;
          }

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] sendDataStream: sending chunk of "
                    << chunk.size() << " bytes\n";
#endif

          if (!socket->send(chunk)) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] sendDataStream: failed to send "
                         "chunk at offset "
                      << totalSent << "\n";
#endif
            return false;
          }

          totalSent += chunk.size();
        }

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] sendDataStream: streaming completed "
                     "successfully\n";
#endif
        return true;
      }

      bool sendChunkedData(std::shared_ptr<pockethttp::SocketWrapper> socket,
          std::function<std::vector<uint8_t>()> dataProvider) {
#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::Http] sendChunkedData: starting chunked upload\n";
#endif

        size_t totalSent = 0;

        while (true) {
          std::vector<uint8_t> chunk = dataProvider();

          if (chunk.empty()) {
            // Send final chunk
            std::string finalChunk = "0\r\n\r\n";
            std::vector<uint8_t> finalChunkData(
                finalChunk.begin(), finalChunk.end());

#ifdef POCKET_HTTP_LOGS
            std::cout
                << "[PocketHttp::Http] sendChunkedData: sending final chunk\n";
#endif

            return socket->send(finalChunkData);
          }

          // Send chunk size in hex + CRLF + data + CRLF
          std::ostringstream chunkHeader;
          chunkHeader << std::hex << chunk.size() << "\r\n";
          std::string chunkHeaderStr = chunkHeader.str();

          std::vector<uint8_t> chunkData;
          chunkData.reserve(chunkHeaderStr.size() + chunk.size() + 2);

          // Add chunk header, data, and trailing CRLF
          chunkData.insert(
              chunkData.end(), chunkHeaderStr.begin(), chunkHeaderStr.end());
          chunkData.insert(chunkData.end(), chunk.begin(), chunk.end());
          chunkData.push_back('\r');
          chunkData.push_back('\n');

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] sendChunkedData: sending chunk of "
                    << chunk.size()
                    << " bytes (total packet: " << chunkData.size()
                    << " bytes)\n";
#endif

          if (!socket->send(chunkData)) {
#ifdef POCKET_HTTP_LOGS
            std::cout
                << "[PocketHttp::Http] sendChunkedData: failed to send chunk\n";
#endif
            return false;
          }

          totalSent += chunk.size();
        }
      }

      CompressionType detectCompression(const Headers& headers) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] detectCompression: checking "
                     "Content-Encoding\n";
#endif
        if (!headers.has("Content-Encoding")) {
          return CompressionType::NONE;
        }

        std::string encoding = headers.get("Content-Encoding");
        std::transform(
            encoding.begin(), encoding.end(), encoding.begin(), ::tolower);

        if (encoding == "gzip") {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] detectCompression: GZIP detected\n";
#endif
          return CompressionType::GZIP;
        } else if (encoding == "deflate") {
#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Http] detectCompression: DEFLATE detected\n";
#endif
          return CompressionType::DEFLATE;
        }

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] detectCompression: no compression "
                     "detected\n";
#endif
        return CompressionType::NONE;
      }

      bool isChunkedEncoding(const Headers& headers) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] isChunkedEncoding: checking "
                     "Transfer-Encoding\n";
#endif
        if (!headers.has("Transfer-Encoding")) {
          return false;
        }

        std::string encoding = headers.get("Transfer-Encoding");
        std::transform(
            encoding.begin(), encoding.end(), encoding.begin(), ::tolower);

        bool isChunked = encoding.find("chunked") != std::string::npos;
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] isChunkedEncoding: "
                  << (isChunked ? "yes" : "no") << "\n";
#endif
        return isChunked;
      }

      size_t parseChunkSize(const std::string& chunkSizeLine) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] parseChunkSize: parsing '"
                  << chunkSizeLine << "'\n";
#endif
        try {
          // Find semicolon in case there are chunk extensions
          size_t semicolonPos = chunkSizeLine.find(';');
          std::string sizeStr = chunkSizeLine.substr(0, semicolonPos);

          size_t chunkSize = std::stoul(sizeStr, nullptr, 16);
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] parseChunkSize: size=" << chunkSize
                    << "\n";
#endif
          return chunkSize;
        } catch (const std::exception&) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] parseChunkSize: failed to parse "
                       "chunk size\n";
#endif
          throw std::runtime_error(
              "Failed to parse chunk size: " + chunkSizeLine);
        }
      }

      void receiveChunkedData(std::shared_ptr<pockethttp::SocketWrapper> socket,
          const std::string& initialData, CompressionType compression,
          std::function<bool(const Response&, const std::vector<uint8_t>&)>&
              onChunk,
          const Response& response,
          std::unique_ptr<Decompress::StreamingGzipDecompressor>&
              gzipDecompressor,
          std::unique_ptr<Decompress::StreamingDeflateDecompressor>&
              deflateDecompressor) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] receiveChunkedData: starting "
                     "memory-limited chunked reception\n";
#endif

        // Single buffer with strict memory limit
        std::vector<uint8_t> parseBuffer;
        parseBuffer.reserve(PARSE_BUFFER_SIZE);
        
        // Add initial data to parse buffer
        parseBuffer.insert(parseBuffer.end(), initialData.begin(), initialData.end());

        // Compression accumulator - separate from parse buffer
        std::vector<uint8_t> compressionBuffer;
        compressionBuffer.reserve(COMPRESSION_BUFFER_SIZE);

        int attempts = 0;
        bool finishedCalled = false;

        while (attempts < MAX_RECEIVE_ATTEMPTS) {
          size_t processedBytes = 0;
          bool processedAnyChunk = false;

          // Process all complete chunks in current buffer
          while (processedBytes < parseBuffer.size()) {
            // Find chunk size line
            size_t searchStart = processedBytes;
            size_t chunkSizeEnd = std::string::npos;
            
            // Look for \r\n in the remaining buffer
            for (size_t i = searchStart; i < parseBuffer.size() - 1; i++) {
              if (parseBuffer[i] == '\r' && parseBuffer[i + 1] == '\n') {
                chunkSizeEnd = i;
                break;
              }
            }

            if (chunkSizeEnd == std::string::npos) {
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveChunkedData: incomplete "
                           "chunk size line, need more data\n";
#endif
              break; // Need more data
            }

            // Extract chunk size line
            std::string chunkSizeLine(
                parseBuffer.begin() + searchStart, parseBuffer.begin() + chunkSizeEnd);
            size_t chunkSize = parseChunkSize(chunkSizeLine);

#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] receiveChunkedData: processing chunk size="
                      << chunkSize << ", current compression buffer="
                      << compressionBuffer.size() << " bytes\n";
#endif

            if (chunkSize == 0) {
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveChunkedData: final chunk "
                           "received, processing remaining data\n";
#endif

              // Process any remaining compressed data before finishing
              if (!compressionBuffer.empty()) {
                if (!processCompressedData(compressionBuffer, compression, onChunk,
                    response, gzipDecompressor, deflateDecompressor)) {
#ifdef POCKET_HTTP_LOGS
                  std::cout << "[PocketHttp::Http] receiveChunkedData: final "
                               "processing failed\n";
#endif
                }
                compressionBuffer.clear();
              }

              // Call finish only once
              if (!finishedCalled) {
                finishDecompression(compression, gzipDecompressor, deflateDecompressor);
                finishedCalled = true;
              }
              return;
            }

            // Calculate positions for chunk data
            size_t chunkDataStart = chunkSizeEnd + 2; // Skip \r\n
            size_t chunkDataEnd = chunkDataStart + chunkSize;
            size_t chunkEnd = chunkDataEnd + 2; // Skip trailing \r\n

            if (chunkEnd > parseBuffer.size()) {
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveChunkedData: incomplete "
                           "chunk data, need " << chunkEnd << " bytes, have "
                      << parseBuffer.size() << " bytes\n";
#endif
              break; // Need more data
            }

            // Extract chunk data
            std::vector<uint8_t> chunkData(
                parseBuffer.begin() + chunkDataStart, parseBuffer.begin() + chunkDataEnd);

            // Handle data based on compression
            if (compression == CompressionType::NONE) {
              // Uncompressed data - process immediately
              if (!onChunk(response, chunkData)) {
#ifdef POCKET_HTTP_LOGS
                std::cout << "[PocketHttp::Http] receiveChunkedData: callback "
                             "requested stop\n";
#endif
                return;
              }
            } else {
              // Compressed data - accumulate in compression buffer
              // Check if adding this chunk would exceed memory limit
              if (compressionBuffer.size() + chunkData.size() > COMPRESSION_BUFFER_SIZE) {
                // Process current buffer first
                if (!compressionBuffer.empty()) {
#ifdef POCKET_HTTP_LOGS
                  std::cout << "[PocketHttp::Http] receiveChunkedData: processing "
                               "compression buffer (" << compressionBuffer.size()
                          << " bytes) before adding new chunk\n";
#endif
                  if (!processCompressedData(compressionBuffer, compression, onChunk,
                          response, gzipDecompressor, deflateDecompressor)) {
#ifdef POCKET_HTTP_LOGS
                    std::cout << "[PocketHttp::Http] receiveChunkedData: "
                                 "compression processing failed\n";
#endif
                    if (!finishedCalled) {
                      finishDecompression(compression, gzipDecompressor, deflateDecompressor);
                      finishedCalled = true;
                    }
                    return;
                  }
                  compressionBuffer.clear();
                }
              }
              
              // Add new chunk data to compression buffer
              compressionBuffer.insert(
                  compressionBuffer.end(), chunkData.begin(), chunkData.end());

              // Process compression buffer when it reaches threshold
              if (compressionBuffer.size() >= PROCESS_THRESHOLD) {
#ifdef POCKET_HTTP_LOGS
                std::cout << "[PocketHttp::Http] receiveChunkedData: processing "
                             "compression buffer (" << compressionBuffer.size()
                        << " bytes) at threshold\n";
#endif
                if (!processCompressedData(compressionBuffer, compression, onChunk,
                        response, gzipDecompressor, deflateDecompressor)) {
#ifdef POCKET_HTTP_LOGS
                  std::cout << "[PocketHttp::Http] receiveChunkedData: "
                               "compression processing failed at threshold\n";
#endif
                  if (!finishedCalled) {
                    finishDecompression(compression, gzipDecompressor, deflateDecompressor);
                    finishedCalled = true;
                  }
                  return;
                }
                compressionBuffer.clear();
              }
            }

            processedBytes = chunkEnd;
            processedAnyChunk = true;
          }

          // Remove processed data from parse buffer
          if (processedBytes > 0) {
            parseBuffer.erase(parseBuffer.begin(), parseBuffer.begin() + processedBytes);
            attempts = 0; // Reset attempts counter on progress
          }

          // If no chunks were processed, try to receive more data
          if (!processedAnyChunk) {
            std::vector<uint8_t> newData = socket->receive();

            if (newData.empty()) {
              attempts++;
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveChunkedData: no data "
                           "received, attempt " << attempts << "\n";
#endif
              std::this_thread::sleep_for(
                  std::chrono::milliseconds(RECEIVE_DELAY_MS));
              continue;
            }

            // Prevent buffer overflow by enforcing strict memory limit
            size_t totalCurrentSize = parseBuffer.size() + compressionBuffer.size();
            size_t availableSpace = (totalCurrentSize < MAX_TOTAL_BUFFER_SIZE) 
                ? MAX_TOTAL_BUFFER_SIZE - totalCurrentSize : 0;

            if (availableSpace == 0) {
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveChunkedData: memory limit "
                           "reached, forcing compression buffer processing\n";
#endif
              // Force process compression buffer to free memory
              if (!compressionBuffer.empty()) {
                if (!processCompressedData(compressionBuffer, compression, onChunk,
                        response, gzipDecompressor, deflateDecompressor)) {
                  if (!finishedCalled) {
                    finishDecompression(compression, gzipDecompressor, deflateDecompressor);
                    finishedCalled = true;
                  }
                  return;
                }
                compressionBuffer.clear();
              }
              
              // Recalculate available space
              availableSpace = MAX_TOTAL_BUFFER_SIZE - parseBuffer.size();
            }

            // Add new data within memory constraints
            size_t dataToAdd = std::min(availableSpace, newData.size());
            if (dataToAdd > 0) {
              parseBuffer.insert(parseBuffer.end(), newData.begin(), 
                  newData.begin() + dataToAdd);
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveChunkedData: added "
                        << dataToAdd << " bytes, total buffer sizes: parse="
                        << parseBuffer.size() << ", compression="
                        << compressionBuffer.size() << "\n";
#endif
            }
          }
        }

        // Process any remaining data
        if (!compressionBuffer.empty()) {
          processCompressedData(compressionBuffer, compression, onChunk, response,
              gzipDecompressor, deflateDecompressor);
        }

        // Ensure finish is called exactly once
        if (!finishedCalled) {
          finishDecompression(compression, gzipDecompressor, deflateDecompressor);
        }
      }

      std::pair<std::string, std::pair<int, std::string>> parseStatusLine(
          const std::string& statusLine) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] parseStatusLine: " << statusLine
                  << "\n";
#endif
        size_t firstSpace = statusLine.find(' ');
        if (firstSpace == std::string::npos) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] parseStatusLine: Invalid status "
                       "line format\n";
#endif
          throw std::runtime_error("Invalid status line format: " + statusLine);
        }

        std::string httpVersion = statusLine.substr(0, firstSpace);
        size_t secondSpace = statusLine.find(' ', firstSpace + 1);

        try {
          if (secondSpace == std::string::npos) {
            int status = std::stoi(statusLine.substr(firstSpace + 1));
            return {httpVersion, {status, ""}};
          } else {
            int status = std::stoi(statusLine.substr(
                firstSpace + 1, secondSpace - firstSpace - 1));
            std::string statusText = statusLine.substr(secondSpace + 1);
            return {httpVersion, {status, statusText}};
          }
        } catch (const std::exception&) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] parseStatusLine: Failed to parse "
                       "status code\n";
#endif
          throw std::runtime_error(
              "Failed to parse status code: " + statusLine);
        }
      }

      Response receiveHeaders(std::shared_ptr<pockethttp::SocketWrapper> socket,
          std::string& remainingData) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] receiveHeaders: receiving headers\n";
#endif
        std::string response;
        response.reserve(2048);

        int attempts = 0;

        while (attempts < MAX_RECEIVE_ATTEMPTS) {
          std::vector<uint8_t> chunk = socket->receive();

          if (chunk.empty()) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] receiveHeaders: empty chunk "
                         "received, attempt "
                      << attempts << "\n";
#endif
            attempts++;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(RECEIVE_DELAY_MS));
            continue;
          }

          response.append(chunk.begin(), chunk.end());

          // Check if we have complete headers
          size_t headerEnd = response.find("\r\n\r\n");
          if (headerEnd != std::string::npos) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] receiveHeaders: complete headers "
                         "received\n";
#endif

            const std::string headerPart = response.substr(0, headerEnd);
            remainingData = response.substr(headerEnd + 4);

            size_t statusLineEnd = headerPart.find("\r\n");
            if (statusLineEnd == std::string::npos) {
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveHeaders: Invalid status "
                           "line in response\n";
#endif
              throw std::runtime_error("Invalid status line in response");
            }

            const std::string statusLine = headerPart.substr(0, statusLineEnd);
            auto [httpVersion, statusInfo] = parseStatusLine(statusLine);
            auto [status, statusText] = statusInfo;

            Response resp;
            resp.version = std::move(httpVersion);
            resp.status = status;
            resp.statusText = std::move(statusText);
            resp.headers = Headers::parse(headerPart.substr(statusLineEnd + 2));

#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] receiveHeaders: status="
                      << resp.status << ", statusText=" << resp.statusText
                      << "\n";
#endif
            return resp;
          }

          attempts = 0; // Reset attempts on successful receive
        }

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] receiveHeaders: Failed to receive "
                     "complete headers\n";
#endif
        throw std::runtime_error("Failed to receive complete headers");
      }

      size_t getContentLength(const Headers& headers) {
#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::Http] getContentLength: checking Content-Length\n";
#endif
        if (!headers.has("Content-Length")) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] getContentLength: no Content-Length "
                       "header\n";
#endif
          return 0;
        }

        try {
          size_t len = std::stoul(headers.get("Content-Length"));
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] getContentLength: Content-Length="
                    << len << "\n";
#endif
          return len;
        } catch (const std::exception&) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] getContentLength: Failed to parse "
                       "Content-Length\n";
#endif
          return 0;
        }
      }

      void setupDecompression(CompressionType compression,
          std::function<bool(const Response&, const std::vector<uint8_t>&)>&
              onChunk,
          const Response& response,
          std::unique_ptr<Decompress::StreamingGzipDecompressor>&
              gzipDecompressor,
          std::unique_ptr<Decompress::StreamingDeflateDecompressor>&
              deflateDecompressor) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] setupDecompression: compression type="
                  << static_cast<int>(compression) << "\n";
#endif

        if (compression == CompressionType::NONE) {
          return;
        }

        // Create callback that calls onChunk and returns the result
        auto decompressionCallback = [&onChunk, &response](const uint8_t* data,
                                         size_t size) -> bool {
          std::vector<uint8_t> chunkData(data, data + size);
          return onChunk(response, chunkData);
        };

        if (compression == CompressionType::GZIP) {
          gzipDecompressor =
              std::make_unique<Decompress::StreamingGzipDecompressor>(
                  decompressionCallback);
        } else if (compression == CompressionType::DEFLATE) {
          deflateDecompressor =
              std::make_unique<Decompress::StreamingDeflateDecompressor>(
                  decompressionCallback);
        }
      }

      bool processCompressedData(const std::vector<uint8_t>& buffer,
          CompressionType compression,
          std::function<bool(const Response&, const std::vector<uint8_t>&)>&
              onChunk,
          const Response& response,
          std::unique_ptr<Decompress::StreamingGzipDecompressor>&
              gzipDecompressor,
          std::unique_ptr<Decompress::StreamingDeflateDecompressor>&
              deflateDecompressor) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] processCompressedData: processing "
                  << buffer.size() << " bytes, compression="
                  << static_cast<int>(compression) << "\n";
#endif

        if (buffer.empty()) {
          return true;
        }

        if (compression == CompressionType::NONE) {
          return onChunk(response, buffer);
        }

        // Process compressed data with streaming decompression
        try {
          if (compression == CompressionType::GZIP && gzipDecompressor) {
            // The decompressor calls onChunk internally as it decompresses data
            return gzipDecompressor->processChunk(buffer.data(), buffer.size());
          } else if (compression == CompressionType::DEFLATE && deflateDecompressor) {
            return deflateDecompressor->processChunk(buffer.data(), buffer.size());
          }
        } catch (const std::exception& e) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] processCompressedData: decompression error: "
                    << e.what() << "\n";
#endif
          return false;
        }

        return true;
      }

      void finishDecompression(CompressionType compression,
          std::unique_ptr<Decompress::StreamingGzipDecompressor>&
              gzipDecompressor,
          std::unique_ptr<Decompress::StreamingDeflateDecompressor>&
              deflateDecompressor) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] finishDecompression: finishing "
                     "compression type=" << static_cast<int>(compression) << "\n";
#endif

        if (compression == CompressionType::NONE) {
          return;
        }

        try {
          if (gzipDecompressor) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] finishDecompression: finishing "
                         "GZIP decompression\n";
#endif
            gzipDecompressor->finish();
          } else if (deflateDecompressor) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] finishDecompression: finishing "
                         "DEFLATE decompression\n";
#endif
            deflateDecompressor->finish();
          }
        } catch (const std::exception& e) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] finishDecompression: finish error: "
                    << e.what() << "\n";
#endif
          // Ignore finish errors as the data may already be complete
        }
      }

      void receiveResponseData(std::shared_ptr<pockethttp::SocketWrapper> socket,
          const std::string& remainingData, const Response& response,
          CompressionType compression,
          std::function<bool(const Response&, const std::vector<uint8_t>&)>&
              onChunk,
          std::unique_ptr<Decompress::StreamingGzipDecompressor>&
              gzipDecompressor,
          std::unique_ptr<Decompress::StreamingDeflateDecompressor>&
              deflateDecompressor) {

        bool chunked = isChunkedEncoding(response.headers);

        if (chunked) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] receiveResponseData: using chunked "
                       "transfer encoding\n";
#endif
          receiveChunkedData(socket, remainingData, compression, onChunk,
              response, gzipDecompressor, deflateDecompressor);
        } else {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] receiveResponseData: using "
                       "content-length or connection close\n";
#endif

          size_t contentLength = getContentLength(response.headers);
          bool hasContentLength = contentLength > 0;

          size_t totalReceived = 0;
          std::vector<uint8_t> buffer;
          buffer.reserve(PROCESS_THRESHOLD);

          // Process any remaining data from header parsing
          if (!remainingData.empty()) {
            buffer.assign(remainingData.begin(), remainingData.end());
            totalReceived += remainingData.size();
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] receiveResponseData: processing "
                         "remaining data from headers, size="
                      << remainingData.size() << "\n";
#endif

            // Process if buffer reaches threshold or for uncompressed data
            if (buffer.size() >= PROCESS_THRESHOLD ||
                compression == CompressionType::NONE) {
              if (!processCompressedData(buffer, compression, onChunk, response,
                      gzipDecompressor, deflateDecompressor)) {
#ifdef POCKET_HTTP_LOGS
                std::cout << "[PocketHttp::Http] receiveResponseData: callback "
                             "requested stop\n";
#endif
                finishDecompression(
                    compression, gzipDecompressor, deflateDecompressor);
                return;
              }
              buffer.clear();
            }
          }

          int attempts = 0;
          bool finishedCalled = false;

          while (attempts < MAX_RECEIVE_ATTEMPTS) {
            // Check if we're done
            if (hasContentLength && totalReceived >= contentLength) {
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveResponseData: received "
                           "all content ("
                        << totalReceived << " bytes)\n";
#endif
              break;
            }

            // Receive more data
            std::vector<uint8_t> chunk = socket->receive();

            if (chunk.empty()) {
              attempts++;
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Http] receiveResponseData: empty "
                           "chunk received, attempt "
                        << attempts << "\n";
#endif
              std::this_thread::sleep_for(
                  std::chrono::milliseconds(RECEIVE_DELAY_MS));

              if (!hasContentLength &&
                  attempts >= MIN_ATTEMPTS_NO_CONTENT_LENGTH) {
#ifdef POCKET_HTTP_LOGS
                std::cout
                    << "[PocketHttp::Http] receiveResponseData: no content "
                       "length and max attempts reached, stopping\n";
#endif
                break;
              }
              continue;
            }

            // Enforce memory limit
            if (buffer.size() + chunk.size() > MAX_TOTAL_BUFFER_SIZE) {
              // Process current buffer first
              if (!buffer.empty()) {
                if (!processCompressedData(buffer, compression, onChunk, response,
                        gzipDecompressor, deflateDecompressor)) {
#ifdef POCKET_HTTP_LOGS
                  std::cout << "[PocketHttp::Http] receiveResponseData: "
                               "processing failed\n";
#endif
                  if (!finishedCalled) {
                    finishDecompression(compression, gzipDecompressor, deflateDecompressor);
                    finishedCalled = true;
                  }
                  return;
                }
                buffer.clear();
              }
            }

            buffer.insert(buffer.end(), chunk.begin(), chunk.end());
            totalReceived += chunk.size();
            attempts = 0;

            // Process buffer when it reaches threshold or for uncompressed data
            if (buffer.size() >= PROCESS_THRESHOLD ||
                (compression == CompressionType::NONE && !buffer.empty()) ||
                (hasContentLength && totalReceived >= contentLength)) {

              if (!processCompressedData(buffer, compression, onChunk, response,
                      gzipDecompressor, deflateDecompressor)) {
#ifdef POCKET_HTTP_LOGS
                std::cout << "[PocketHttp::Http] receiveResponseData: callback "
                             "requested stop\n";
#endif
                if (!finishedCalled) {
                  finishDecompression(compression, gzipDecompressor, deflateDecompressor);
                  finishedCalled = true;
                }
                return;
              }

              buffer.clear();
            }
          }

          // Process any remaining data in buffer
          if (!buffer.empty()) {
            processCompressedData(buffer, compression, onChunk, response,
                gzipDecompressor, deflateDecompressor);
          }

          // Finish decompression if not already called
          if (!finishedCalled) {
            finishDecompression(compression, gzipDecompressor, deflateDecompressor);
          }
        }
      }

    public:
      Http() : timeout_(DEFAULT_TIMEOUT) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] Constructor called\n";
#endif
      }

      explicit Http(int64_t timeout) : timeout_(timeout) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] Constructor called with timeout="
                  << timeout << "\n";
#endif
      }

      // Disable copy constructor and assignment
      Http(const Http&) = delete;
      Http& operator=(const Http&) = delete;

      // Enable move constructor and assignment
      Http(Http&&) = default;
      Http& operator=(Http&&) = default;

      void request(Request request,
          std::function<bool(const Response&, const std::vector<uint8_t>&)>
              onChunk) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] request: url=" << request.url << "\n";
#endif

        Remote remote = pockethttp::utils::parseUrl(request.url);
        auto socket = pockethttp::SocketPool::getSocket(remote.protocol, remote.host, remote.port);

        if (!socket) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] request: Failed to establish socket "
                       "connection\n";
#endif
          throw std::runtime_error("Failed to establish socket connection");
        }

        setDefaultHeaders(request, remote.host);

        if (!sendHttpRequestInChunks(socket, request, remote.path)) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] request: Failed to send request\n";
#endif
          throw std::runtime_error("Failed to send request");
        }

        std::string remainingData;
        Response response = receiveHeaders(socket, remainingData);

        CompressionType compression = detectCompression(response.headers);
        std::unique_ptr<Decompress::StreamingGzipDecompressor> gzipDecompressor;
        std::unique_ptr<Decompress::StreamingDeflateDecompressor>
            deflateDecompressor;

        setupDecompression(compression, onChunk, response, gzipDecompressor,
            deflateDecompressor);
        receiveResponseData(socket, remainingData, response, compression,
            onChunk, gzipDecompressor, deflateDecompressor);

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] request: finished\n";
#endif
      }

      void requestStream(Request request,
          std::function<std::vector<uint8_t>()> dataProvider,
          std::function<bool(const Response&, const std::vector<uint8_t>&)>
              onChunk,
          size_t contentLength = 0) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] requestStream: url=" << request.url
                  << ", contentLength=" << contentLength << "\n";
#endif

        Remote remote = pockethttp::utils::parseUrl(request.url);
        auto socket = pockethttp::SocketPool::getSocket(remote.protocol, remote.host, remote.port);

        if (!socket) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] requestStream: Failed to establish "
                       "socket connection\n";
#endif
          throw std::runtime_error("Failed to establish socket connection");
        }

        setDefaultHeadersForStreaming(request, remote.host, contentLength);

        if (!sendHttpRequestHeaders(socket, request, remote.path)) {
#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Http] requestStream: Failed to send headers\n";
#endif
          throw std::runtime_error("Failed to send headers");
        }

        bool useChunked =
            request.headers.has("Transfer-Encoding") &&
            request.headers.get("Transfer-Encoding").find("chunked") !=
                std::string::npos;

        if (useChunked) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] requestStream: using chunked transfer encoding for upload" << std::endl;
#endif
          if (!sendChunkedData(socket, dataProvider)) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] requestStream: Failed to send chunked data" << std::endl;
#endif
            throw std::runtime_error("Failed to send chunked data");
          }
        } else {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Http] requestStream: using content-length for upload" << std::endl;
#endif
          if (!sendDataStream(socket, dataProvider)) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Http] requestStream: Failed to send stream data" << std::endl;
#endif
            throw std::runtime_error("Failed to send stream data");
          }
        }

        std::string remainingData;
        Response response = receiveHeaders(socket, remainingData);

        CompressionType compression = detectCompression(response.headers);
        std::unique_ptr<Decompress::StreamingGzipDecompressor> gzipDecompressor;
        std::unique_ptr<Decompress::StreamingDeflateDecompressor>
            deflateDecompressor;

        setupDecompression(compression, onChunk, response, gzipDecompressor,
            deflateDecompressor);
        receiveResponseData(socket, remainingData, response, compression,
            onChunk, gzipDecompressor, deflateDecompressor);

#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::Http] requestStream: finished" << std::endl;
#endif
      }
  };

} // namespace pockethttp

#endif