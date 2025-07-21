#ifndef POCKET_HTTP_DECOMPRESS_HPP
#define POCKET_HTTP_DECOMPRESS_HPP

// Include all compression components
#include "Decompress/Constants.hpp"
#include "Decompress/MinizWrapper.hpp"
#include "Decompress/StreamingDecompressor.hpp"
#include "Decompress/StreamingDeflateDecompressor.hpp"
#include "Decompress/StreamingGzipDecompressor.hpp"
#include "Decompress/StreamingGzipParser.hpp"

namespace pockethttp {
  namespace Decompress {

    // Re-export main classes for backward compatibility
    using GzipDecompressor = StreamingGzipDecompressor;
    using DeflateDecompressor = StreamingDeflateDecompressor;

  } // namespace Decompress
} // namespace pockethttp

#endif // POCKET_HTTP_DECOMPRESS_HPP