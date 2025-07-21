#include <pockethttp/Headers.hpp>
#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace pockethttp {

  Headers Headers::parse(const std::string& rawHeaders) {
    Headers headers;

    std::vector<std::string> lines;
    size_t start = 0;
    size_t end = rawHeaders.find("\r\n");
    while (end != std::string::npos) {
      lines.push_back(rawHeaders.substr(start, end - start));
      start = end + 2;
      end = rawHeaders.find("\r\n", start);
    }
    lines.push_back(rawHeaders.substr(start));

    for (const std::string& line : lines) {
      size_t colonPos = line.find(':');
      if (colonPos != std::string::npos) {
        std::string key = line.substr(0, colonPos);
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        std::string value = line.substr(colonPos + 1);

        value.erase(0, value.find_first_not_of(' '));
        headers.set(key, value);
      }
    }

    return headers;
  }

  void Headers::set(const std::string& key, const std::string& value) {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_[lowerKey] = value;
  }

  std::string Headers::get(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    auto it = headers_.find(lowerKey);
    return (it != headers_.end()) ? it->second : "";
  }

  bool Headers::has(const std::string& key) const {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    return headers_.find(lowerKey) != headers_.end();
  }

  void Headers::remove(const std::string& key) {
    std::string lowerKey = key;
    std::transform(
        lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    headers_.erase(lowerKey);
  }

  std::string Headers::dump() const {
    std::string result;
    for (const auto& header : headers_) {
      result += header.first + ": " + header.second + "\r\n";
    }

    return result;
  }

  std::vector<std::string> Headers::keys() const {
    std::vector<std::string> keys;
    for (const auto& header : headers_) {
      keys.push_back(header.first);
    }
    return keys;
  }

} // namespace pockethttp