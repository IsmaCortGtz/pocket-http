#include "pockethttp/Buffer.hpp"
#include <cstddef>
#include <cstring>

namespace pockethttp {

  namespace Buffer {

    size_t find(const unsigned char* buffer, const size_t& size, const unsigned char* to_find, const size_t& to_find_size) {
      if (buffer == nullptr || size == 0 || to_find == nullptr || to_find_size == 0) {
        return pockethttp::Buffer::error; // No data to search
      }

      if (size < to_find_size) {
        return pockethttp::Buffer::error; // Not enough data to find the pattern
      }

      for (size_t i = 0; i <= size - to_find_size; ++i) {
        if (std::memcmp(buffer + i, to_find, to_find_size) == 0) {
          return i;
        }
      }

      return pockethttp::Buffer::error; // Not found
    }

    bool equal(const unsigned char* buffer, const unsigned char* to_find, const size_t& size) {
      if (buffer == nullptr || to_find == nullptr || size == 0) {
        return false; // Invalid input
      }
      return std::memcmp(buffer, to_find, size) == 0;
    }

  } // namespace Buffer

} // namespace pockethttp