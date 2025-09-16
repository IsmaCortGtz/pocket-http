// This example demonstrates a basic HTTP GET request using the pockethttp library.
// Compiled using amalgamated version of the library.

#include <pockethttp.hpp>
#include <iostream>
#include <cstring>
#include <functional>

int main (int argc, char* argv[]) {
  // Check arguments
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <url> <encoding (optional = 'identity')>" << std::endl;
    return 1;
  }

  // Set encoding
  std::string encoding = "identity";
  if (argc >= 3) encoding = argv[2];

  // Create request
  pockethttp::Request req;
  req.method = "GET";
  req.url = argv[1];
  req.headers.set("Accept-Encoding", encoding);

  // Set response callback
  pockethttp::Response res;
  std::string resBody = "";
  res.body_callback = [&resBody](const unsigned char* buffer, const size_t& size) {
    resBody.append(reinterpret_cast<const char*>(buffer), size);
  };

  // Create HTTP client
  pockethttp::Http http;
  bool success = http.request(req, res);
  if (!success) {
    std::cerr << "Request failed." << std::endl;
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