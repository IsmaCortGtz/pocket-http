#include "pockethttp/Sockets/SocketPool.hpp"
#include "pockethttp/Sockets/TCPSocket.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace pockethttp {

  std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> SocketPool::pool_;
  
  std::map<std::string, pockethttp::SocketCreator> SocketPool::protocols_ = {
    {"http", []() { return std::make_shared<pockethttp::TCPSocket>(); }}
  };

} // namespace pockethttp