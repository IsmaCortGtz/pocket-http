#include "pockethttp/Request.hpp"
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>


namespace pockethttp {

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
          throw std::invalid_argument("Unsupported protocol: " + remote.protocol);
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

    std::string url_encode(const std::string& decoded, const std::string& safe) {
      std::string out;
      char hexChars[] = "0123456789ABCDEF";

      for (unsigned char c : decoded) {
        if (isalnum(c) || safe.find(c) != std::string::npos) {
          out += c;
        } else if (c == ' ') {
          out += '+';
        } else {
          out += '%';
          out += hexChars[(c >> 4) & 0x0F];
          out += hexChars[c & 0x0F];
        }
      }

      return out;
    }

    std::string url_decode(const std::string& encoded) {
      std::string out;
      
      for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
          std::string hex = encoded.substr(i + 1, 2);
          out += static_cast<char>(std::stoi(hex, nullptr, 16));
          i += 2;
        } else if (encoded[i] == '+') {
          out += ' ';
        } else {
          out += encoded[i];
        }
      }

      return out;
    }

    std::string normalize_url(const std::string &raw_url) {
      // Replace spaces with %20
      std::string url = url_decode(raw_url);
      size_t pos = 0;
      while ((pos = url.find(' ', pos)) != std::string::npos) {
        url.replace(pos, 1, "%20");
        pos += 3; // Move past the inserted %20
      }

      return url;
    }

  } // namespace utils

} // namespace pockethttp