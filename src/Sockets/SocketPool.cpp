#include "pockethttp/Sockets/SocketPool.hpp"
#include "pockethttp/Sockets/TCPSocket.hpp"
#include "pockethttp/Results.hpp"

#if defined(USE_POCKET_HTTP_MBEDTLS)
  #include "pockethttp/Sockets/MbedTLSSocket.hpp"
#elif defined(USE_POCKET_HTTP_BEARSSL)
  #include "pockethttp/Sockets/TLSSocket.hpp"
#endif


#include <map>
#include <memory>
#include <string>
#include <vector>

namespace pockethttp {

  int SocketPool::last_result = pockethttp::HttpResult::SUCCESS;

  std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> SocketPool::pool_;
  
  std::map<std::string, pockethttp::SocketCreator> SocketPool::protocols_ = {
    {"http", []() { return std::make_shared<pockethttp::TCPSocket>(); }},
    #if defined(USE_POCKET_HTTP_MBEDTLS)
      {"https", []() { return std::make_shared<pockethttp::MbedTLSSocket>(); }},
    #elif defined(USE_POCKET_HTTP_BEARSSL)
      {"https", []() { return std::make_shared<pockethttp::TLSSocket>(); }},
    #endif
  };

} // namespace pockethttp
