#ifndef POCKET_HTTP_DECOMPRESS_STREAMING_GZIP_DECOMPRESSOR_HPP
#define POCKET_HTTP_DECOMPRESS_STREAMING_GZIP_DECOMPRESSOR_HPP

#include "Constants.hpp"
#include "StreamingDecompressor.hpp"
#include "StreamingGzipParser.hpp"
#include <functional>
#include <memory>

#ifdef POCKET_HTTP_LOGS
#include <iostream>
#endif

namespace pockethttp {
  namespace Decompress {

    class StreamingGzipDecompressor {
      public:
        using OutputCallback = std::function<bool(const uint8_t*, size_t)>;

        explicit StreamingGzipDecompressor(OutputCallback callback)
            : output_callback_(std::move(callback)),
              processing_deflate_data_(false) {

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] StreamingGzipDecompressor "
                       "initialized"
                    << std::endl;
#endif
        }

        // Process a chunk of compressed GZIP data - returns false if callback
        // requests stop
        bool processChunk(const uint8_t* data, size_t size) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Processing GZIP chunk: "
                    << size << " bytes" << std::endl;
#endif

          size_t offset = 0;

          // First, try to parse header if not done yet
          if (!parser_.isHeaderParsed()) {
            offset = processHeader(data, size);
          }

          // Process remaining data as deflate stream (minus footer)
          if (processing_deflate_data_ && offset < size) {
            return processDeflateData(data, size, offset);
          }

          return true;
        }

        // Finish decompression
        void finish() {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Finishing GZIP decompression"
                    << std::endl;
#endif
          if (decompressor_) {
            decompressor_->finish();
          }
        }

        bool isFinished() const {
          return decompressor_ && decompressor_->isFinished();
        }

        size_t getTotalDecompressed() const {
          return decompressor_ ? decompressor_->getTotalProcessed() : 0;
        }

        uint32_t getExpectedSize() const {
          return parser_.getUncompressedSize();
        }

      private:
        StreamingGzipParser parser_;
        std::unique_ptr<StreamingDecompressor> decompressor_;
        OutputCallback output_callback_;
        bool processing_deflate_data_;

        size_t processHeader(const uint8_t* data, size_t size) {
          size_t consumed = parser_.processHeaderData(data, size);

          if (parser_.isHeaderParsed()) {
            initializeDecompressor();
          }

          return consumed;
        }

        void initializeDecompressor() {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] GZIP header parsed, "
                       "initializing decompressor"
                    << std::endl;
#endif
          // Convert bool-returning callback to void callback for
          // StreamingDecompressor
          auto wrapped_callback = [this](const uint8_t* data, size_t size) {
            output_callback_(data, size);
          };

          decompressor_ =
              std::make_unique<StreamingDecompressor>(wrapped_callback, true);

          // Process any deflate data that was in the header buffer
          auto deflate_data = parser_.getDeflateDataFromHeader();
          if (!deflate_data.empty()) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Decompress] Processing deflate data "
                         "from header buffer: "
                      << deflate_data.size() << " bytes" << std::endl;
#endif
            decompressor_->processData(
                deflate_data.data(), deflate_data.size());
          }

          processing_deflate_data_ = true;
        }

        bool processDeflateData(
            const uint8_t* data, size_t size, size_t offset) {
          size_t remaining = size - offset;

          // Reserve last 8 bytes for footer processing
          if (remaining > GzipConstants::FOOTER_SIZE) {
            size_t deflate_size = remaining - GzipConstants::FOOTER_SIZE;

#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Decompress] Processing deflate data: "
                      << deflate_size << " bytes" << std::endl;
#endif

            decompressor_->processData(data + offset, deflate_size);
            offset += deflate_size;
          }

          // Process potential footer data
          if (offset < size) {
#ifdef POCKET_HTTP_LOGS
            std::cout
                << "[PocketHttp::Decompress] Processing potential footer data: "
                << (size - offset) << " bytes" << std::endl;
#endif
            parser_.processFooterData(data + offset, size - offset);
          }

          return true;
        }
    };

  } // namespace Decompress
} // namespace pockethttp

#endif