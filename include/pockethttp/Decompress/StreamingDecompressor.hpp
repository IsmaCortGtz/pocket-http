#ifndef POCKET_HTTP_DECOMPRESS_STREAMING_DECOMPRESSOR_HPP
#define POCKET_HTTP_DECOMPRESS_STREAMING_DECOMPRESSOR_HPP

#include <string>
#include <functional>
#include <stdexcept>
#include <vector>

#include "Constants.hpp"
#include "MinizWrapper.hpp"

#ifdef POCKET_HTTP_LOGS
#include <iostream>
#endif

namespace pockethttp {
  namespace Decompress {

    // Streaming decompressor for minimal memory usage
    class StreamingDecompressor {
      public:
        using OutputCallback = std::function<void(const uint8_t*, size_t)>;

        explicit StreamingDecompressor(
            OutputCallback callback, bool is_gzip = true)
            : stream_(is_gzip), output_callback_(std::move(callback)),
              stream_finished_(false) {
          output_buffer_.resize(StreamConstants::CHUNK_SIZE);

#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Decompress] StreamingDecompressor initialized, "
                 "GZIP mode: "
              << (is_gzip ? "true" : "false")
              << ", buffer size: " << StreamConstants::CHUNK_SIZE << " bytes"
              << std::endl;
#endif
        }

        ~StreamingDecompressor() {
#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::Decompress] StreamingDecompressor destroyed"
              << std::endl;
#endif
        }

        // Non-copyable, movable
        StreamingDecompressor(const StreamingDecompressor&) = delete;
        StreamingDecompressor& operator=(const StreamingDecompressor&) = delete;

        StreamingDecompressor(StreamingDecompressor&& other) noexcept
            : stream_(std::move(other.stream_)),
              output_buffer_(std::move(other.output_buffer_)),
              output_callback_(std::move(other.output_callback_)),
              stream_finished_(other.stream_finished_) {
          other.stream_finished_ = true; // Mark other as finished

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] StreamingDecompressor moved"
                    << std::endl;
#endif
        }

        StreamingDecompressor& operator=(
            StreamingDecompressor&& other) noexcept {
          if (this != &other) {
            stream_ = std::move(other.stream_);
            output_buffer_ = std::move(other.output_buffer_);
            output_callback_ = std::move(other.output_callback_);
            stream_finished_ = other.stream_finished_;
            other.stream_finished_ = true;
          }
          return *this;
        }

        // Process compressed data chunk
        void processData(const uint8_t* data, size_t size) {
          if (stream_finished_)
            return;

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Processing " << size
                    << " bytes of compressed data" << std::endl;
#endif

          auto* mz_stream = stream_.get();
          mz_stream->next_in = data;
          mz_stream->avail_in = size;

          while (mz_stream->avail_in > 0 && !stream_finished_) {
            processInflationCycle();
          }
        }

        // Finish decompression
        void finish() {
          if (stream_finished_)
            return;

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Finishing decompression"
                    << std::endl;
#endif

          auto* mz_stream = stream_.get();
          mz_stream->next_in = nullptr;
          mz_stream->avail_in = 0;

          int result;
          do {
            result = performInflation(MZ_FINISH);
          } while (result != MZ_STREAM_END && mz_stream->avail_out == 0);

          stream_finished_ = true;

#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::Decompress] Decompression finished, total "
                       "output: "
                    << mz_stream->total_out << " bytes" << std::endl;
#endif
        }

        bool isFinished() const {
          return stream_finished_;
        }
        size_t getTotalProcessed() const {
          return stream_.isInitialized() ? stream_.get()->total_out : 0;
        }

      private:
        MinizStream stream_;
        std::vector<uint8_t> output_buffer_;
        OutputCallback output_callback_;
        bool stream_finished_;

        void processInflationCycle() {
          int result = performInflation(MZ_NO_FLUSH);

          if (result == MZ_STREAM_END) {
#ifdef POCKET_HTTP_LOGS
            std::cout
                << "[PocketHttp::Decompress] Decompression stream finished"
                << std::endl;
#endif
            stream_finished_ = true;
          }
        }

        int performInflation(int flush) {
          auto* mz_stream = stream_.get();
          mz_stream->next_out = output_buffer_.data();
          mz_stream->avail_out = output_buffer_.size();

          int result = mz_inflate(mz_stream, flush);
          validateInflationResult(result);

          size_t decompressed_size =
              output_buffer_.size() - mz_stream->avail_out;
          if (decompressed_size > 0 && output_callback_) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::Decompress] Decompressed "
                      << decompressed_size << " bytes" << std::endl;
#endif
            output_callback_(output_buffer_.data(), decompressed_size);
          }

          return result;
        }

        void validateInflationResult(int result) {
          if (result == MZ_STREAM_ERROR || result == MZ_DATA_ERROR ||
              result == MZ_MEM_ERROR) {
#ifdef POCKET_HTTP_LOGS
            std::cerr << "[PocketHttp::Decompress] Decompression error: "
                      << result << std::endl;
#endif
            throw std::runtime_error(
                "Decompression error: " + std::to_string(result));
          }
        }
    };

  } // namespace Decompress
} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_STREAMING_DECOMPRESSOR_HPP