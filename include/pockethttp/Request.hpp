#ifndef POCKET_HTTP_REQUEST_HPP
#define POCKET_HTTP_REQUEST_HPP

#include <pockethttp/Headers.hpp>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace pockethttp {

  struct Request {
      std::string version = "HTTP/1.1"; // Default HTTP version
      std::string method;
      std::string url;
      Headers headers;
      std::vector<uint8_t> body;
  };

  struct Remote {
      std::string protocol;
      std::string host;
      std::string path;
      uint16_t port;
  };

  namespace utils {

    Remote parseUrl(const std::string& url) {
      Remote remote;

      if (url.empty()) {
        throw std::invalid_argument("URL cannot be empty");
      }

      // Regex para parsear URL completa
      // Captura: protocol://host:port/path
      std::regex urlRegex(R"(^(https?):\/\/([^:\/\s]+)(?::(\d+))?(\/.*)?$)");
      std::smatch matches;

      if (!std::regex_match(url, matches, urlRegex)) {
        throw std::invalid_argument("Invalid URL format");
      }

      // Extraer componentes
      remote.protocol = matches[1].str();
      remote.host = matches[2].str();

      // Puerto - usar default si no está especificado
      if (matches[3].matched) {
        remote.port = static_cast<uint16_t>(std::stoi(matches[3].str()));
      } else {
        // Puerto por defecto según protocolo
        if (remote.protocol == "https") {
          remote.port = 443;
        } else if (remote.protocol == "http") {
          remote.port = 80;
        } else {
          throw std::invalid_argument(
              "Unsupported protocol: " + remote.protocol);
        }
      }

      // Path - usar "/" si no está especificado
      if (matches[4].matched) {
        remote.path = matches[4].str();
      } else {
        remote.path = "/";
      }

      return remote;
    }

    std::string getProtocol(const std::string& url) {
      std::regex protocolRegex(R"(^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/)");
      std::smatch match;

      if (std::regex_search(url, match, protocolRegex)) {
        return match[1].str();
      } else {
        throw std::invalid_argument("URL does not contain a valid protocol");
      }
    }

  } // namespace utils

} // namespace pockethttp

#endif // POCKET_HTTP_REQUEST_HPP