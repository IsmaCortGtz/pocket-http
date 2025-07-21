#ifndef POCKET_HTTP_DECOMPRESS_STREAMING_GZIP_PARSER_HPP
#define POCKET_HTTP_DECOMPRESS_STREAMING_GZIP_PARSER_HPP

#include "Constants.hpp"
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef POCKET_HTTP_LOGS
#include <iomanip>
#include <iostream>
#endif

namespace pockethttp {
  namespace Decompress {

    // Stream-based GZIP parser for minimal memory usage
    class StreamingGzipParser {
      public:
        StreamingGzipParser() : header_offset_(0), header_parsed_(false) {
          header_buffer_.reserve(StreamConstants::MAX_HEADER_SIZE);
          footer_buffer_.reserve(GzipConstants::FOOTER_SIZE);

#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Decompress] StreamingGzipParser initialized"
              << std::endl;
#endif
        }

        // Returns number of bytes consumed from input
        size_t processHeaderData(const uint8_t* data, size_t size) {
          if (header_parsed_)
            return 0;

          size_t old_size = header_buffer_.size();
          size_t bytes_needed =
              std::min(size, StreamConstants::MAX_HEADER_SIZE - old_size);

          header_buffer_.insert(
              header_buffer_.end(), data, data + bytes_needed);

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Processing header data: "
                    << bytes_needed
                    << " bytes, total buffer size: " << header_buffer_.size()
                    << std::endl;
#endif

          // Try to parse header if we have enough data
          if (header_buffer_.size() >= GzipConstants::MIN_SIZE) {
            try {
              parseHeader();
            } catch (const std::runtime_error&) {
              // Need more data or invalid header
              if (header_buffer_.size() > StreamConstants::MAX_HEADER_SIZE) {
#ifdef POCKET_HTTP_LOGS
                std::cerr << "[PocketHttp::Decompress] GZIP header too large: "
                          << header_buffer_.size() << " bytes" << std::endl;
#endif
                throw std::runtime_error("GZIP header too large");
              }
#ifdef POCKET_HTTP_LOGS
              std::cout << "[PocketHttp::Decompress] Need more header data for "
                           "parsing"
                        << std::endl;
#endif
            }
          }

          return bytes_needed;
        }

        bool isHeaderParsed() const {
          return header_parsed_;
        }
        size_t getHeaderOffset() const {
          return header_offset_;
        }

        // Get deflate data from header buffer (remaining after header)
        std::vector<uint8_t> getDeflateDataFromHeader() {
          if (!header_parsed_ || header_offset_ >= header_buffer_.size()) {
            return {};
          }

          std::vector<uint8_t> deflate_data(
              header_buffer_.begin() + header_offset_, header_buffer_.end());

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Extracted "
                    << deflate_data.size()
                    << " bytes of deflate data from header buffer" << std::endl;
#endif

          // Clear header buffer to save memory
          header_buffer_.clear();
          header_buffer_.shrink_to_fit();

          return deflate_data;
        }

        // Process footer data (last 8 bytes)
        void processFooterData(const uint8_t* data, size_t size) {
          footer_buffer_.insert(footer_buffer_.end(), data, data + size);
          if (footer_buffer_.size() > GzipConstants::FOOTER_SIZE) {
            // Keep only last 8 bytes
            footer_buffer_.erase(footer_buffer_.begin(),
                footer_buffer_.end() - GzipConstants::FOOTER_SIZE);
          }

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Processed " << size
                    << " bytes of footer data, buffer size: "
                    << footer_buffer_.size() << std::endl;
#endif
        }

        uint32_t getUncompressedSize() const {
          if (footer_buffer_.size() < 4)
            return 0;

          size_t pos = footer_buffer_.size() - 4;
          uint32_t size = footer_buffer_[pos] | (footer_buffer_[pos + 1] << 8) |
                          (footer_buffer_[pos + 2] << 16) |
                          (footer_buffer_[pos + 3] << 24);

#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Decompress] Uncompressed size from footer: "
              << size << " bytes" << std::endl;
#endif

          return size;
        }

      private:
        std::vector<uint8_t> header_buffer_;
        std::vector<uint8_t> footer_buffer_;
        size_t header_offset_;
        bool header_parsed_;

        void parseHeader() {
          if (header_buffer_.size() < GzipConstants::MIN_SIZE) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::Decompress] Incomplete GZIP header, "
                         "need at least "
                      << GzipConstants::MIN_SIZE << " bytes, got "
                      << header_buffer_.size() << std::endl;
#endif
            throw std::runtime_error("Incomplete GZIP header");
          }

          const uint8_t* data = header_buffer_.data();
          validateMagicAndMethod(data);

          header_offset_ = GzipConstants::BASE_HEADER_SIZE;
          const uint8_t flags = data[3];

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Processing GZIP flags: 0x"
                    << std::hex << (int)flags << std::dec << std::endl;
#endif

          processOptionalFields(data, flags);
          header_parsed_ = true;

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] GZIP header parsing "
                       "completed, total header size: "
                    << header_offset_ << " bytes" << std::endl;
#endif
        }

        void validateMagicAndMethod(const uint8_t* data) {
          if (data[0] != GzipConstants::MAGIC_1 ||
              data[1] != GzipConstants::MAGIC_2) {
#ifdef POCKET_HTTP_LOGS
            std::cerr
                << "[PocketHttp::Decompress] Invalid GZIP magic number: 0x"
                << std::hex << (int)data[0] << " 0x" << (int)data[1] << std::dec
                << std::endl;
#endif
            throw std::runtime_error("Invalid GZIP magic number");
          }

          if (data[2] != GzipConstants::METHOD_DEFLATE) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::Decompress] Unsupported GZIP "
                         "compression method: "
                      << (int)data[2] << std::endl;
#endif
            throw std::runtime_error("Unsupported GZIP compression method");
          }

#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Decompress] GZIP header validation successful"
              << std::endl;
#endif
        }

        void processOptionalFields(const uint8_t* data, uint8_t flags) {
          if (flags & GzipConstants::FLAG_FEXTRA) {
            processExtraField(data);
          }

          if (flags & GzipConstants::FLAG_FNAME) {
            header_offset_ = skipNullTerminatedString(header_offset_, "FNAME");
          }

          if (flags & GzipConstants::FLAG_FCOMMENT) {
            header_offset_ =
                skipNullTerminatedString(header_offset_, "FCOMMENT");
          }

          if (flags & GzipConstants::FLAG_FHCRC) {
            header_offset_ += 2;
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Decompress] Processed FHCRC field"
                      << std::endl;
#endif
          }
        }

        void processExtraField(const uint8_t* data) {
          if (header_buffer_.size() < header_offset_ + 2) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::Decompress] Incomplete GZIP FEXTRA field"
                      << std::endl;
#endif
            throw std::runtime_error("Incomplete GZIP FEXTRA");
          }

          const uint16_t extra_len =
              data[header_offset_] | (data[header_offset_ + 1] << 8);
          header_offset_ += 2 + extra_len;

#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Decompress] Processed FEXTRA field, length: "
              << extra_len << std::endl;
#endif
        }

        size_t skipNullTerminatedString(
            size_t start_offset, const char* field_name) {
          size_t offset = start_offset;
          while (
              offset < header_buffer_.size() && header_buffer_[offset] != 0) {
            offset++;
          }

          if (offset >= header_buffer_.size()) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::Decompress] Invalid GZIP " << field_name
                      << " field - missing null terminator" << std::endl;
#endif
            throw std::runtime_error(std::string("Invalid GZIP ") + field_name);
          }

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Processed " << field_name
                    << " field" << std::endl;
#endif

          return offset + 1; // Skip null terminator
        }
    };

  } // namespace Decompress
} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_STREAMING_GZIP_PARSER_HPP