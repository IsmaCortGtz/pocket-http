#ifndef POCKET_HTTP_SOCKET_POOL_HPP
#define POCKET_HTTP_SOCKET_POOL_HPP

#include "pockethttp/Logs.hpp"
#include "pockethttp/Timestamp.hpp"
#include "pockethttp/Sockets/SocketWrapper.hpp"
#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <functional>

namespace pockethttp {

  using SocketCreator = std::function<std::shared_ptr<pockethttp::SocketWrapper>()>;

  class SocketPool {
    private:
      static std::map<std::string, pockethttp::SocketCreator> protocols_;
      static std::map<std::string, std::vector<std::shared_ptr<pockethttp::SocketWrapper>>> pool_;

      static std::string buildPoolKey(const std::string& protocol, const std::string& host, const uint16_t port) {
        pockethttp_log("[SocketPool] buildPoolKey" << protocol << ":" << port);
        return protocol + ":" + host + ":" + std::to_string(port);
      }

      static std::shared_ptr<pockethttp::SocketWrapper> findAvailableSocket(std::vector<std::shared_ptr<pockethttp::SocketWrapper>>& connections) {
        pockethttp_log("[SocketPool] findAvailableSocket: searching for available socket");

        for (auto& conn : connections) {
          if (conn.use_count() == 1 && conn->isConnected()) {
            pockethttp_log("[SocketPool] findAvailableSocket: found available socket");
            return conn;
          }
        }

        pockethttp_log("[SocketPool] findAvailableSocket: no available socket found");
        return nullptr;
      }

      static std::shared_ptr<pockethttp::SocketWrapper> createNewSocket(const std::string& protocol, const std::string& host, const uint16_t port) {
        pockethttp_log("[SocketPool] createNewSocket: creating new socket for " << host << ":" << port);
        
        auto socketCreator = protocols_.find(protocol);
        if (socketCreator == protocols_.end()) {
          pockethttp_log("[SocketPool] createNewSocket: protocol not found: " << protocol);
          return nullptr;
        }

        auto newSocket = socketCreator->second();
        if (newSocket->connect(host, port)) {
          pockethttp_log("[SocketPool] createNewSocket: connection successful");
          return newSocket;
        } else {
          pockethttp_log("[SocketPool] createNewSocket: connection failed");
          return nullptr;
        }
      }

    public:
      static std::shared_ptr<pockethttp::SocketWrapper> getSocket(const std::string& protocol, const std::string& host, uint16_t port) {
        pockethttp_log("[SocketPool] getSocket: protocol=" << protocol << ", host=" << host << ", port=" << port);
        cleanupUnused();

        const std::string key = buildPoolKey(protocol, host, port);
        auto& connections = pool_[key];

        // Try to reuse existing connection
        if (auto socket = findAvailableSocket(connections)) {
          pockethttp_log("[SocketPool] getSocket: reusing existing socket");
          return socket;
        }

        // Create new connection
        if (auto newSocket = createNewSocket(protocol, host, port)) {
          connections.push_back(newSocket);
          pockethttp_log("[SocketPool] getSocket: new socket created and added to pool");
          return newSocket;
        }

        pockethttp_log("[SocketPool] getSocket: failed to get socket");
        return nullptr;
      }

      static void registerProtocol(const std::string& protocol, pockethttp::SocketCreator creator) {
        pockethttp_log("[SocketPool] registerProtocol: protocol=" << protocol);
        protocols_[protocol] = creator;
      }

      static void cleanupUnused(int64_t timeout = 30000) {
        pockethttp_log("[SocketPool] cleanupUnused: cleaning up unused connections");
        const int64_t currentTime = pockethttp::Timestamp::getCurrentTimestamp();

        for (auto& [key, connections] : pool_) {
          connections.erase(
            std::remove_if(connections.begin(), connections.end(),
              [timeout, currentTime] (std::shared_ptr<pockethttp::SocketWrapper>& conn) {
                const int64_t connectionAge = currentTime - conn->getTimestamp();
                const bool shouldRemove =
                  (conn.use_count() == 1 && connectionAge > timeout) ||
                  !conn->isConnected();

                if (shouldRemove) {
                  pockethttp_log("[SocketPool] cleanupUnused: disconnecting socket");
                  conn->disconnect();
                }
                
                return shouldRemove;
              }),
            connections.end()
          );
        }
      }

      static void cleanupAll() {
        pockethttp_log("[SocketPool] cleanupAll: disconnecting all sockets and clearing pool");
        
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