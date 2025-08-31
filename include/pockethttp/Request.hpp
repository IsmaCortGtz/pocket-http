#ifndef POCKET_HTTP_REQUEST_HPP
#define POCKET_HTTP_REQUEST_HPP

#include "pockethttp/Buffer.hpp"
#include "pockethttp/Headers.hpp"
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>


namespace pockethttp {
  
  typedef std::function<bool(unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read)> RequestCallback;

  struct FormDataItem {
    std::string name;

    // Only one of the following two are required
    std::string value = "";
    RequestCallback value_callback = nullptr;

    // When value_callback is set (if one is missing an exception will be thrown):
    std::string filename = "";
    std::string content_type = "";
    size_t content_length = pockethttp::Buffer::error; /** Needed only when use_chunked_transfer_encoding is false */
  };

  struct FormDataRequest {
    std::string method;
    std::string url;
    Headers headers;
    std::vector<FormDataItem> form_data;
  };

  struct Request {
    std::string method;
    std::string url;
    Headers headers;

    // Only one of the following two are required
    std::string body = "";
    RequestCallback body_callback = nullptr;
  };

  struct Remote {
    std::string protocol;
    std::string host;
    std::string path;
    uint16_t port;
  };

  struct FormDataSendState {
    std::vector<FormDataItem>::iterator current_item;
    unsigned short current_line = 1;
    size_t current_offset = 0;
    bool sending_last_boundary = false;
    size_t last_boundary_offset = 0;
  };

  namespace utils {

    Remote parseUrl(const std::string& url);
    std::string getProtocol(const std::string& url);
    
  } // namespace utils

} // namespace pockethttp

#endif // POCKET_HTTP_REQUEST_HPP