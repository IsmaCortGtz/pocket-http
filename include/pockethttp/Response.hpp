#ifndef POCKET_HTTP_RESPONSE_HPP
#define POCKET_HTTP_RESPONSE_HPP

#include "pockethttp/Headers.hpp"
#include <string>
#include <vector>
#include <functional>

#define POCKETHTTP_RESPONSE_MAX_STATUS_TEXT_SIZE 16

namespace pockethttp {

  enum ChunkedStatus {
    CHUNKED_STATUS_HEX,
    CHUNKED_STATUS_LF,
    CHUNKED_STATUS_DATA,
    CHUNKED_STATUS_POSTLF,
    CHUNKED_STATUS_DONE,
    CHUNKED_STATUS_ERROR
  };

  struct ChunkedResponseState {
    ChunkedStatus status = CHUNKED_STATUS_HEX;
    size_t content_length = 0;
    size_t remaining_content_length = 0;
    unsigned char hexindex = 0;
    char hexbuffer[POCKETHTTP_RESPONSE_MAX_STATUS_TEXT_SIZE + 1];
  };

  struct Response {
      std::string version; // HTTP version, e.g., "HTTP/1.1"

      uint16_t status;
      std::string statusText;
      
      Headers headers;

      std::function<void(const unsigned char* buffer, const size_t& size)> body_callback = nullptr;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_RESPONSE_HPP