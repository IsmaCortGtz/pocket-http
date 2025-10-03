#include <pockethttp/pockethttp.hpp>
#include <iostream>
#include <cstring>
#include <functional>
#include <fstream>

int main (int argc, char* argv[]) {
  // Check arguments
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
    return 1;
  }

  // Create request
  pockethttp::Request req;
  req.method = "GET";
  req.url = argv[1];

  // Set response callback
  pockethttp::Response res;
  std::ofstream file("downloaded_video.mp4", std::ios::binary);
  res.body_callback = [&file](const unsigned char* buffer, const size_t& size) {
    file.write(reinterpret_cast<const char*>(buffer), size);
  };

  // Create HTTP client
  pockethttp::Http http;
  int success = http.request(req, res);
  if (success <= 0) {
    std::cerr << "Request failed: " << pockethttp::getErrorMessage(success) << std::endl;
    std::cout << std::endl;
    return 1;
  }
  
  std::cout << std::endl << std::endl;
  std::cout <<  res.version << " " << res.status << " " << res.statusText << std::endl;
  std::cout << res.headers.dump() << std::endl;
  return 0;
}