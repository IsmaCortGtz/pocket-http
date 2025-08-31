#include <pockethttp/pockethttp.hpp>
#include <iostream>
#include <cstring>

int main (int argc, char* argv[]) {


  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <url> <encoding (optional = 'identity')>" << std::endl;
    return 1;
  }

  std::string encoding = "identity";
  if (argc >= 3) {
    encoding = argv[2];
  }

  pockethttp::Request req;
  req.method = "GET";
  req.url = argv[1];
  req.headers.set("Accept-Encoding", encoding);

  pockethttp::Response res;
  std::string resBody = "";
  res.body_callback = [&resBody](unsigned char* buffer, size_t& size) {
    resBody.append(reinterpret_cast<const char*>(buffer), size);
    size = 0;
  };

  pockethttp::Http http;
  bool success = http.request(req, res);

  if (!success) {
    std::cerr << "Request failed" << std::endl;
    return 1;
  }
  
  std::cout << std::endl << std::endl << "Response successful: " << res.status << " " << res.statusText << std::endl;
  std::cout << "Response headers:" << std::endl;
  std::cout << res.headers.dump() << std::endl << std::endl;
  std::cout << "Response body:" << std::endl << std::endl;
  std::cout << resBody << std::endl;
  return 0;
}