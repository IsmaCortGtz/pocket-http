#ifndef POCKET_HTTP_DECOMPRESS_MINIZ_WRAPPER_HPP
#define POCKET_HTTP_DECOMPRESS_MINIZ_WRAPPER_HPP

#include <miniz/miniz.h>
#include <string>
#include <cstring>
#include <stdexcept>

namespace pockethttp {
  namespace Decompress {

    // RAII wrapper for mz_stream
    class MinizStream {
      public:
        explicit MinizStream(bool is_gzip = true) : initialized_(false) {
          std::memset(&stream_, 0, sizeof(stream_));

          int window_bits =
              is_gzip ? -MZ_DEFAULT_WINDOW_BITS : MZ_DEFAULT_WINDOW_BITS;
          int result = mz_inflateInit2(&stream_, window_bits);

          if (result != MZ_OK) {
            throw std::runtime_error("Failed to initialize inflate stream: " +
                                     std::to_string(result));
          }

          initialized_ = true;
        }

        ~MinizStream() {
          if (initialized_)
            mz_inflateEnd(&stream_);
        }

        // Non-copyable, movable
        MinizStream(const MinizStream&) = delete;
        MinizStream& operator=(const MinizStream&) = delete;

        MinizStream(MinizStream&& other) noexcept
            : stream_(other.stream_), initialized_(other.initialized_) {
          other.initialized_ = false;
          std::memset(&other.stream_, 0, sizeof(other.stream_));
        }

        MinizStream& operator=(MinizStream&& other) noexcept {
          if (this != &other) {
            if (initialized_)
              mz_inflateEnd(&stream_);
            stream_ = other.stream_;
            initialized_ = other.initialized_;
            other.initialized_ = false;
            std::memset(&other.stream_, 0, sizeof(other.stream_));
          }
          return *this;
        }

        mz_stream* get() {
          return &stream_;
        }
        const mz_stream* get() const {
          return &stream_;
        }

        bool isInitialized() const {
          return initialized_;
        }

      private:
        mz_stream stream_;
        bool initialized_;
    };

  } // namespace Decompress
} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_MINIZ_WRAPPER_HPP