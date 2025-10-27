#include <pockethttp/pockethttp.hpp>
#include <iostream>
#include <cstring>
#include <functional>

int main (int argc, char* argv[]) {
  // Check arguments
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <url> <redirects [true|false]> <encoding (optional = 'identity')>" << std::endl;
    return 1;
  }

  // Set encoding
  std::string encoding = "identity";
  if (argc >= 4) encoding = argv[3];

  // Create request
  pockethttp::Request req;
  req.method = "GET";
  req.url = argv[1];
  req.headers.set("Accept-Encoding", encoding);
  req.max_redirects = 5;

  if (argc >= 3 && (std::string(argv[2]) == "true")) {
    std::cout << "Follow redirects: " << argv[2] << std::endl;
    req.follow_redirects = true;
  } else {
    std::cout << "Not following redirects." << std::endl;
    req.follow_redirects = false;
  }

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