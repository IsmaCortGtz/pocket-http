#include "pockethttp/Sockets/SocketPool.hpp"
#include "pockethttp/Sockets/TCPSocket.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL
#include "pockethttp/Sockets/TLSSocket.hpp"
#endif // USE_POCKET_HTTP_BEARSSL

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace pockethttp {

  std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> SocketPool::pool_;
  
  std::map<std::string, pockethttp::SocketCreator> SocketPool::protocols_ = {
    {"http", []() { return std::make_shared<pockethttp::TCPSocket>(); }},
    #ifdef USE_POCKET_HTTP_BEARSSL
    {"https", []() { return std::make_shared<pockethttp::TLSSocket>(); }},
    #endif // USE_POCKET_HTTP_BEARSSL
  };

} // namespace pockethttp
