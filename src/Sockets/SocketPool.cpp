#include <pockethttp/Sockets/SocketPool.hpp>
#include <pockethttp/Sockets/TCPSocket.hpp>

#ifdef POCKET_HTTP_USE_BEARSSL
#include <pockethttp/TLS/TLSSocket.hpp>
#endif // POCKET_HTTP_USE_BEARSSL

namespace pockethttp {

  std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> SocketPool::pool_;
  
  std::map<std::string, pockethttp::SocketCreator> SocketPool::protocols_ = {
    {"http", []() { return std::make_shared<pockethttp::TCPSocket>(); }},
#ifdef POCKET_HTTP_USE_BEARSSL
    {"https", []() { return std::make_shared<pockethttp::TLSSocket>(); }}
#endif // POCKET_HTTP_USE_BEARSSL
  };

} // namespace pockethttp