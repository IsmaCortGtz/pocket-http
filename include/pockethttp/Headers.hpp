#ifndef POCKET_HTTP_HEADERS_HPP
#define POCKET_HTTP_HEADERS_HPP

#include <map>
#include <string>
#include <vector>

namespace pockethttp {

  class Headers {
    public:
      static Headers parse(const std::string& rawHeaders);
      
      void load(const std::string& rawHeaders);
      std::string dump() const;
      std::vector<std::string> keys() const;
      std::string get(const std::string& key) const;
      void set(const std::string& key, const std::string& value);
      bool has(const std::string& key) const;
      void remove(const std::string& key);

    private:
      std::map<std::string, std::string> headers_;
  };

} // namespace pockethttp

#endif // POCKET_HTTP_HEADERS_HPP