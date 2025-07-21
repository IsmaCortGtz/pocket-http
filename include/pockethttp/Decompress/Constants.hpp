#ifndef POCKET_HTTP_DECOMPRESS_CONSTANTS_HPP
#define POCKET_HTTP_DECOMPRESS_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

namespace pockethttp {
  namespace Decompress {

    // GZIP format constants
    struct GzipConstants {
        static constexpr uint8_t MAGIC_1 = 0x1f;
        static constexpr uint8_t MAGIC_2 = 0x8b;
        static constexpr uint8_t METHOD_DEFLATE = 8;
        static constexpr size_t MIN_SIZE = 18;
        static constexpr size_t BASE_HEADER_SIZE = 10;
        static constexpr size_t FOOTER_SIZE = 8;

        // Flags
        static constexpr uint8_t FLAG_FEXTRA = 0x04;
        static constexpr uint8_t FLAG_FNAME = 0x08;
        static constexpr uint8_t FLAG_FCOMMENT = 0x10;
        static constexpr uint8_t FLAG_FHCRC = 0x02;
    };

    // Stream processing constants
    struct StreamConstants {
        static constexpr size_t CHUNK_SIZE = 16384;    // 16KB chunks
        static constexpr size_t MAX_HEADER_SIZE = 512; // Max header buffer size
    };

  } // namespace Decompress
} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_CONSTANTS_HPP