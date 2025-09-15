#include "pockethttp/Logs.hpp"
#include "pockethttp/Decompress.hpp"
#include <miniz/miniz.h>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <cstddef>
#include <cstdint>

namespace pockethttp {

  Decompressor::Decompressor(DecompressionAlgorithm algorithm) : algorithm(algorithm) {}

  Decompressor::~Decompressor() {
    pockethttp_log("[Decompressor] Cleaning up decompressor");
    inflateEnd(&this->stream);
  }

  DecompressionState Decompressor::init() {
    
    if (this->algorithm == DecompressionAlgorithm::DEFLATE || this->algorithm == DecompressionAlgorithm::GZIP) {
      
      memset(&this->stream, 0, sizeof(this->stream));
      int window_bits = this->algorithm == DecompressionAlgorithm::GZIP ? -MZ_DEFAULT_WINDOW_BITS : MZ_DEFAULT_WINDOW_BITS;
      
      int ret = mz_inflateInit2(&this->stream, window_bits);
      if (ret != MZ_OK) {
        pockethttp_error("[Decompressor] Failed to initialize decompressor: " << ret);
        return DecompressionState::DECOMPRESS_ERROR;
      }

      pockethttp_log("[Decompressor] Decompressor initialized successfully: " << ret);

      this->state = DecompressionState::INITIALIZED;
    } else {
      this->state = DecompressionState::DECOMPRESS_ERROR;
    }

    return this->state;
  }

  size_t Decompressor::get_gzip_header_length(const uint8_t* data, size_t size) {
    // The minimum length of a GZIP header is 10 bytes.
    if (size < 10) return 0;

    // Check GZIP magic numbers (0x1f 0x8b)
    if (data[0] != 0x1f || data[1] != 0x8b) return 0;

    // The compression method must be DEFLATE (8)
    if (data[2] != 8) return 0;

    const uint8_t flags = data[3];
    size_t header_len = 10;

    // FEXTRA: Extra field
    if (flags & 0x04) {
      if (header_len + 2 > size) return 0; // Incomplete
      uint16_t extra_len = data[header_len] | (data[header_len + 1] << 8);
      header_len += 2 + extra_len;
    }

    // FNAME: File name (null-terminated)
    if (flags & 0x08) {
      while (header_len < size && data[header_len] != 0) {
        header_len++;
      }
      if (header_len < size) header_len++; // Include the NUL
    }

    // FCOMMENT: Comment (null-terminated)
    if (flags & 0x10) {
      while (header_len < size && data[header_len] != 0) {
          header_len++;
      }
      if (header_len < size) header_len++; // Include the NUL
    }
    // FHCRC: CRC16 of the header
    if (flags & 0x02) {
      header_len += 2;
    }

    return (header_len <= size) ? header_len : 0;
  }

  DecompressionState Decompressor::decompress(
    const unsigned char* input, 
    size_t input_size, 
    std::function<void(const unsigned char* buffer, const size_t& size)> output_callback
  ) {
    pockethttp_log("[Decompressor] Decompress called with " << input_size << " bytes of input data.");
    if (input == nullptr || input_size == 0) {
      this->state = DecompressionState::DECOMPRESS_ERROR;
      return this->state;
    }

    size_t header_length = this->algorithm == DecompressionAlgorithm::GZIP && !this->header_processed ? this->get_gzip_header_length(input, input_size) : 0;
    if (header_length > 0) this->header_processed = true;
    pockethttp_log("[Decompressor] GZIP header length: " << header_length << "/" << input_size << " bytes.");

    size_t out_size = 0;
    this->stream.next_in = input + header_length;
    this->stream.avail_in = input_size - header_length;
    this->state = DecompressionState::DECOMPRESSING;

    pockethttp_log("[Decompressor] Decompressing " << this->stream.avail_in << " bytes of data.");

    unsigned char output[POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE];
    bool done = false;

    while(!done) {
      done = true;
      int status;

      this->stream.next_out = output;
      this->stream.avail_out = POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE;

      status = mz_inflate(&this->stream, MZ_NO_FLUSH);
      pockethttp_log("[Decompressor] mz_inflate status: " << status);

      if (this->stream.avail_out != POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE) {
        if (status == MZ_OK || status == MZ_STREAM_END) {
          out_size = POCKET_HTTP_DECOMPRESS_OUTPUT_CHUNK_SIZE - this->stream.avail_out;
          output_callback(output, out_size);
        }
      }

      switch (status) {
        case MZ_OK:
          done = false;
          this->state = DecompressionState::DECOMPRESSING;
          break;
        case MZ_BUF_ERROR:
          done = true;
          this->state = DecompressionState::DECOMPRESSING;
          break;
        case MZ_STREAM_END:
          done = true;
          this->state = DecompressionState::FINISHED;
          break;
        default:
          pockethttp_error("[Decompressor] Decompression error: " << status);
          done = true;
          this->state = DecompressionState::DECOMPRESS_ERROR;
          break;
      }
    }
    
    return this->state;
  }

  const uint8_t* Decompressor::getPendingInputPtr() const {
    return this->stream.next_in;
  }

  size_t Decompressor::getPendingInputSize() const {
    return this->stream.avail_in;
  }

} // namespace pockethttp