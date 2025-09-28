#ifndef POCKET_HTTP_DECOMPRESS_HPP
#define POCKET_HTTP_DECOMPRESS_HPP

#if __has_include("miniz.h")
  #include <miniz.h>
#elif __has_include("miniz/miniz.h")
  #include <miniz/miniz.h>
#else
  #error "Cannot find miniz.h or miniz/miniz.h"
#endif

#include <cstddef>
#include <cstdint>
#include <functional>

#define POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE 16384 // 16 kb

namespace pockethttp {

  enum DecompressionAlgorithm {
    NONE,
    GZIP,
    DEFLATE
  };

  enum DecompressionState {
    INITIALIZED,
    DECOMPRESSING,
    FINISHED,
    DECOMPRESS_ERROR
  };

  class Decompressor {
    private:
      mz_stream stream;
      DecompressionAlgorithm algorithm;

      bool header_processed = false;
      size_t get_gzip_header_length(const uint8_t* data, size_t size);
      DecompressionState state;
      
    public:
      Decompressor(DecompressionAlgorithm algorithm);
      ~Decompressor();

      DecompressionState init();
      DecompressionState decompress(
        const unsigned char* input, 
        size_t input_size, 
        std::function<void(const unsigned char* buffer, const size_t& size)> output_callback
      );
      
      const uint8_t* getPendingInputPtr() const;
      size_t getPendingInputSize() const;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_HPP