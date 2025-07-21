#ifndef POCKET_HTTP_DECOMPRESS_STREAMING_DEFLATE_DECOMPRESSOR_HPP
#define POCKET_HTTP_DECOMPRESS_STREAMING_DEFLATE_DECOMPRESSOR_HPP

#include <functional>
#include <memory>

#include "StreamingDecompressor.hpp"

#ifdef POCKET_HTTP_LOGS
#include <iostream>
#endif

namespace pockethttp {
  namespace Decompress {

    class StreamingDeflateDecompressor {
      public:
        using OutputCallback = std::function<bool(const uint8_t*, size_t)>;

        explicit StreamingDeflateDecompressor(OutputCallback callback)
            : output_callback_(std::move(callback)) {

          // Convert bool-returning callback to void callback for
          // StreamingDecompressor
          auto wrapped_callback = [this](const uint8_t* data, size_t size) {
            output_callback_(data, size);
          };

          decompressor_ =
              std::make_unique<StreamingDecompressor>(wrapped_callback, false);

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] StreamingDeflateDecompressor "
                       "initialized"
                    << std::endl;
#endif
        }

        // Process a chunk of compressed deflate data - returns false if
        // callback requests stop
        bool processChunk(const uint8_t* data, size_t size) {
          if (decompressor_) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Decompress] Processing deflate chunk: "
                      << size << " bytes" << std::endl;
#endif
            decompressor_->processData(data, size);
          }
          return true;
        }

        void finish() {
          if (decompressor_) {
#ifdef POCKET_HTTP_LOGS
            std::cout
                << "[PocketHttp::Decompress] Finishing deflate decompression"
                << std::endl;
#endif
            decompressor_->finish();
          }
        }

        bool isFinished() const {
          return decompressor_ && decompressor_->isFinished();
        }

        size_t getTotalDecompressed() const {
          return decompressor_ ? decompressor_->getTotalProcessed() : 0;
        }

      private:
        std::unique_ptr<StreamingDecompressor> decompressor_;
        OutputCallback output_callback_;
    };

  } // namespace Decompress
} // namespace pockethttp

#endif