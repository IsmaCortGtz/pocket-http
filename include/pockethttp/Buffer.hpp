#ifndef POCKET_HTTP_BUFFER_HPP
#define POCKET_HTTP_BUFFER_HPP

#include <cstddef>

namespace pockethttp {

  namespace Buffer {

    const size_t error = static_cast<size_t>(-1);

    size_t find(const unsigned char* buffer, const size_t& size, const unsigned char* to_find, const size_t& to_find_size);
    
    bool equal(const unsigned char* buffer, const unsigned char* to_find, const size_t& size);

  }

} // namespace pockethttp

#endif // POCKET_HTTP_BUFFER_HPP