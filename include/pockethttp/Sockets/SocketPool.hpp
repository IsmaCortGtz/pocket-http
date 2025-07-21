#ifndef POCKET_HTTP_SOCKET_POOL_HPP
#define POCKET_HTTP_SOCKET_POOL_HPP

#include <pockethttp/Sockets/SocketWrapper.hpp>
#include <pockethttp/Timestamp.hpp>
#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <functional>
#ifdef POCKET_HTTP_LOGS
#include <iostream>
#endif

namespace pockethttp {

  using SocketCreator = std::function<std::shared_ptr<pockethttp::SocketWrapper>()>;

  class SocketPool {
    private:
      static std::map<std::string, pockethttp::SocketCreator> protocols_;
      static std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> pool_;

      static std::string buildPoolKey(const std::string& protocol, const std::string& host, uint16_t port) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::SocketPool] buildPoolKey: " << protocol
                  << ":" << host << ":" << port << "\n";
#endif
        return protocol + ":" + host + ":" + std::to_string(port);
      }

      static std::shared_ptr<pockethttp::SocketWrapper> findAvailableSocket(std::vector<std::shared_ptr<pockethttp::SocketWrapper>>& connections) {
#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::SocketPool] findAvailableSocket: searching for "
               "available socket\n";
#endif
        for (auto& conn : connections) {
          if (conn.use_count() == 1 && conn->isConnected()) {
#ifdef POCKET_HTTP_LOGS
            std::cout << "[PocketHttp::SocketPool] findAvailableSocket: found "
                         "available socket\n";
#endif
            return conn;
          }
        }
#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::SocketPool] findAvailableSocket: no available "
               "socket found\n";
#endif
        return nullptr;
      }

      static std::shared_ptr<pockethttp::SocketWrapper> createNewSocket(const std::string& protocol, const std::string& host, uint16_t port) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::SocketPool] createNewSocket: creating new "
                     "socket for "
                  << host << ":" << port << "\n";
#endif
        auto socketCreator = protocols_.find(protocol);
        if (socketCreator == protocols_.end()) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::SocketPool] createNewSocket: protocol not found: " << protocol << "\n";
#endif
          return nullptr;
        }

        auto newSocket = socketCreator->second();
        if (newSocket->connect(host, port)) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::SocketPool] createNewSocket: connection "
                       "successful\n";
#endif
          return newSocket;
        } else {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::SocketPool] createNewSocket: connection "
                       "failed\n";
#endif
          return nullptr;
        }
      }

    public:
      static std::shared_ptr<pockethttp::SocketWrapper> getSocket(const std::string& protocol, const std::string& host, uint16_t port) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::SocketPool] getSocket: protocol=" << protocol
                  << ", host=" << host << ", port=" << port << "\n";
#endif
        cleanupUnused();

        const std::string key = buildPoolKey(protocol, host, port);
        auto& connections = pool_[key];

        // Try to reuse existing connection
        if (auto socket = findAvailableSocket(connections)) {
#ifdef POCKET_HTTP_LOGS
          std::cout << "[PocketHttp::SocketPool] getSocket: reusing existing "
                       "socket\n";
#endif
          return socket;
        }

        // Create new connection
        if (auto newSocket = createNewSocket(protocol, host, port)) {
          connections.push_back(newSocket);
#ifdef POCKET_HTTP_LOGS
          std::cout
              << "[PocketHttp::SocketPool] getSocket: new socket created and "
                 "added to pool\n";
#endif
          return newSocket;
        }

#ifdef POCKET_HTTP_LOGS
        std::cout
            << "[PocketHttp::SocketPool] getSocket: failed to get socket\n";
#endif
        return nullptr;
      }

      static void registerProtocol(const std::string& protocol, pockethttp::SocketCreator creator) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::SocketPool] registerProtocol: protocol=" << protocol << "\n";
#endif
        protocols_[protocol] = creator;
      }

      static void cleanupUnused(int64_t timeout = 30000) {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::SocketPool] cleanupUnused: cleaning up unused connections" << std::endl;
#endif

        const int64_t currentTime =
            pockethttp::Timestamp::getCurrentTimestamp();

        for (auto& [key, connections] : pool_) {
          connections.erase(
              std::remove_if(connections.begin(), connections.end(),
                  [timeout, currentTime](
                      std::shared_ptr<pockethttp::SocketWrapper>& conn) {
                    const int64_t connectionAge =
                        currentTime - conn->getTimestamp();
                    const bool shouldRemove =
                        (conn.use_count() == 1 && connectionAge > timeout) ||
                        !conn->isConnected();

                    if (shouldRemove) {
#ifdef POCKET_HTTP_LOGS
                      std::cout << "[PocketHttp::SocketPool] cleanupUnused: "
                                   "disconnecting socket\n";
#endif
                      conn->disconnect();
                    }
                    return shouldRemove;
                  }),
              connections.end());
        }
      }

      static void cleanupAll() {
#ifdef POCKET_HTTP_LOGS
        std::cout << "[PocketHttp::SocketPool] cleanupAll: disconnecting all "
                     "sockets and clearing pool\n";
#endif

        for (auto& [key, connections] : pool_) {
          for (auto& conn : connections) {
            conn->disconnect();
          }
        }
        pool_.clear();
      }

      static size_t getPoolSize() {
        size_t totalConnections = 0;
        for (const auto& [key, connections] : pool_) {
          totalConnections += connections.size();
        }
        return totalConnections;
      }

      static size_t getPoolCount() {
        return pool_.size();
      }
  };

} // namespace pockethttp

#endif
