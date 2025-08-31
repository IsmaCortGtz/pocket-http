#ifndef POCKET_HTTP_RESPONSE_HPP
#define POCKET_HTTP_RESPONSE_HPP

#include "pockethttp/Headers.hpp"
#include <string>
#include <vector>
#include <functional>

namespace pockethttp {

  struct Response {
      std::string version; // HTTP version, e.g., "HTTP/1.1"

      uint16_t status;
      std::string statusText;
      
      Headers headers;

      std::function<void(unsigned char* buffer, size_t& size)> body_callback = nullptr;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_RESPONSE_HPP