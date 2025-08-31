#ifndef POCKET_HTTP_HTTP_HPP
#define POCKET_HTTP_HTTP_HPP

#include "pockethttp/Request.hpp"
#include "pockethttp/Response.hpp"
#include "pockethttp/Sockets/SocketWrapper.hpp"

namespace pockethttp {

  class Http {
    private:
      int64_t timeout_;
      bool request(
        pockethttp::Remote& remote,
        std::string& method,
        pockethttp::Headers& headers,
        pockethttp::Response& response,
        RequestCallback& body_callback
      );

      void setDefaultHeaders(pockethttp::Headers& headers, pockethttp::Remote& remote);
      std::string generateBoundary();

      size_t parseStatusLine(
        pockethttp::Response& response, 
        std::shared_ptr<SocketWrapper> socket, 
        unsigned char* buffer, 
        const size_t& buffer_size,
        size_t& total_bytes_read
      );

      size_t parseHeaders(
        pockethttp::Response& response, 
        std::shared_ptr<SocketWrapper> socket, 
        unsigned char* buffer, 
        const size_t& buffer_size,
        size_t& prev_data_size
      );

      bool handleChunked(
        pockethttp::Response& response, 
        std::shared_ptr<SocketWrapper> socket,
        std::function<void(unsigned char* buffer, size_t& size)> body_callback,
        unsigned char* buffer, 
        const size_t buffer_size,
        size_t& prev_data_size
      );

    public:
      Http();
      Http(int64_t timeout);
      ~Http();

      bool request(pockethttp::Request& req, pockethttp::Response& res);
      bool request(pockethttp::FormDataRequest& req, pockethttp::Response& res);
  };
  
} // namespace pockethttp

#endif // POCKET_HTTP_HTTP_HPP