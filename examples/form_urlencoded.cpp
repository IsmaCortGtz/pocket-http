#include <pockethttp/pockethttp.hpp>
#include <iostream>
#include <cstring>
#include <functional>

int main (int argc, char* argv[]) {
  // Check arguments
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <url> <encoding (optional = 'identity')>" << std::endl;
    return 1;
  }

  // Create request
  pockethttp::Request req;
  req.method = "POST";
  req.url = argv[1];
  req.headers.set("Content-Type", "application/x-www-form-urlencoded");
  req.body = "name=John&last_name=Doe+Smith&age=30"; // The body must be an already URL-encoded string

  // Set response callback
  pockethttp::Response res;
  std::string resBody = "";
  res.body_callback = [&resBody](const unsigned char* buffer, const size_t& size) {
    resBody.append(reinterpret_cast<const char*>(buffer), size);
  };

  // Create HTTP client
  pockethttp::Http http;
  int success = http.request(req, res);
  if (success < 1) {
    std::cerr << "Request failed: " << pockethttp::getErrorMessage(success) << std::endl;
    std::cout << "Pulled body: " << std::endl;
    std::cout << std::endl;
    std::cout << resBody << std::endl;
    std::cout << std::endl;
    return 1;
  }
  
  std::cout << std::endl << std::endl;
  std::cout <<  res.version << " " << res.status << " " << res.statusText << std::endl;
  std::cout << res.headers.dump() << std::endl;
  std::cout << resBody << std::endl << std::endl;
  return 0;
}