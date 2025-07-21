#ifndef POCKET_HTTP_RESPONSE_HPP
#define POCKET_HTTP_RESPONSE_HPP

#include <pockethttp/Headers.hpp>
#include <string>
#include <vector>

namespace pockethttp {

  struct Response {
      std::string version; // HTTP version, e.g., "HTTP/1.1"
      uint16_t status;
      std::string statusText;
      Headers headers;
      std::vector<uint8_t> body;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_RESPONSE_HPP