#ifndef POCKET_HTTP_RESULTS_HPP
#define POCKET_HTTP_RESULTS_HPP

#include <string>

namespace pockethttp {

  typedef enum {

    // SOCKET

    HOSTNAME_RESOLUTION_FAILED = -500,
    OPEN_TCP_SOCKET_FAILED = -499,

    FAILED_TO_INIT_TLS = -498,
    FAILED_TO_ALLOCATE_TLS_CONTEXT = -497,
    FAILED_TO_ALLOCATE_IO_BUFFER = -496,
    FAILED_TO_LOAD_CERTIFICATES = -495,

    TLS_FLUSH_ERROR = -494,
    INVALID_CERTIFICATE = -493,

    // HTTP

    FORMDATA_FILENAME_MISSING = -200,
    FORMDATA_CONTENT_TYPE_MISSING = -199,

    FAILED_SEND_DATA = -198,
    FAILED_SEND_CHUNKED_DATA = -197,
    REQUEST_BODY_CALLBACK_ERROR = -196,

    PARSE_STATUS_LINE_FAILED = -195,
    PARSE_HEADERS_FAILED = -194,
    PARSE_RES_BODY_FAILED = -193,
    DECOMPRESS_RES_FAILED = -192,
    PARSE_CHUNKED_RES_FAILED = -191,
    MAX_REDIRECTS_REACHED = -190,

    // GENERIC
    UNKNOWN_ERROR = 0,
    SUCCESS = 1,
  
  } HttpResult;



  inline std::string getErrorMessage(pockethttp::HttpResult code) {
    switch (code) {

      // SOCKET

      case HttpResult::HOSTNAME_RESOLUTION_FAILED:
        return "HOSTNAME_RESOLUTION_FAILED";
      case HttpResult::OPEN_TCP_SOCKET_FAILED:
        return "OPEN_TCP_SOCKET_FAILED";

      case HttpResult::FAILED_TO_INIT_TLS:
        return "FAILED_TO_INIT_TLS";
      case HttpResult::FAILED_TO_ALLOCATE_TLS_CONTEXT:
        return "FAILED_TO_ALLOCATE_TLS_CONTEXT";
      case HttpResult::FAILED_TO_ALLOCATE_IO_BUFFER:
        return "FAILED_TO_ALLOCATE_IO_BUFFER";
      case HttpResult::FAILED_TO_LOAD_CERTIFICATES:
        return "FAILED_TO_LOAD_CERTIFICATES";      

      case HttpResult::TLS_FLUSH_ERROR:
        return "TLS_FLUSH_ERROR";
      case HttpResult::INVALID_CERTIFICATE:
        return "INVALID_CERTIFICATE";
      
      // HTTP

      case HttpResult::FORMDATA_FILENAME_MISSING:
        return "FORMDATA_FILENAME_MISSING";
      case HttpResult::FORMDATA_CONTENT_TYPE_MISSING:
        return "FORMDATA_CONTENT_TYPE_MISSING";
      
      case HttpResult::FAILED_SEND_DATA:
        return "FAILED_SEND_DATA";
      case HttpResult::FAILED_SEND_CHUNKED_DATA:
        return "FAILED_SEND_CHUNKED_DATA";
      case HttpResult::REQUEST_BODY_CALLBACK_ERROR:
        return "REQUEST_BODY_CALLBACK_ERROR";
      
      case HttpResult::PARSE_STATUS_LINE_FAILED:
        return "PARSE_STATUS_LINE_FAILED";
      case HttpResult::PARSE_HEADERS_FAILED:
        return "PARSE_HEADERS_FAILED";
      case HttpResult::PARSE_RES_BODY_FAILED:
        return "PARSE_RES_BODY_FAILED";
      case HttpResult::DECOMPRESS_RES_FAILED:
        return "DECOMPRESS_RES_FAILED";
      case HttpResult::PARSE_CHUNKED_RES_FAILED:
        return "PARSE_CHUNKED_RES_FAILED";
      case HttpResult::MAX_REDIRECTS_REACHED:
        return "MAX_REDIRECTS_REACHED";

      // GENERIC

      case HttpResult::UNKNOWN_ERROR:
        return "UNKNOWN_ERROR";
      case HttpResult::SUCCESS:
        return "SUCCESS";
      default:
        return "INVALID ERROR (" + std::to_string(code) + ")";

    }
  }

  inline std::string getErrorMessage(int code) {
    return pockethttp::getErrorMessage(static_cast<pockethttp::HttpResult>(code));
  }

  inline std::string getErrorMessage(short code) {
    return pockethttp::getErrorMessage(static_cast<pockethttp::HttpResult>(code));
  }


} // namespace pockethttp

#endif // POCKET_HTTP_RESULTS_HPP