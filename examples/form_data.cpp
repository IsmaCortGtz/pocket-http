#include <pockethttp/pockethttp.hpp>
#include <iostream>
#include <cstring>
#include <functional>
#include <fstream>

// TODO: Fix FormDataRequest in Http.cpp

int main (int argc, char* argv[]) {
  // Check arguments
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
    return 1;
  }

  // Create request
  // This request uses multipart/form-data to upload a file and some text fields
  // For url-encoded forms, see form_urlencoded.cpp
  pockethttp::FormDataRequest req;
  req.method = "POST";
  req.url = argv[1];
  req.form_data.push_back({"name", "John"});
  req.form_data.push_back({"last_name", "Doe"});

  pockethttp::FormDataItem fileItem;
  fileItem.name = "file";
  fileItem.filename = "test.o";
  fileItem.content_type = "application/octet-stream";
  // fileItem.content_length = 11; // optional; If some is missing, chunked transfer encoding will be used
  
  std::ifstream file(argv[0], std::ios::binary);

  fileItem.value_callback = [&file](unsigned char* data, size_t* read_data, const size_t max_size, const size_t total_read) {
    if (total_read == 0) {
      file.clear();
      file.seekg(0, std::ios::beg);
    }
    
    if (file.eof()) {
      *read_data = 0;
      return false;
    }

    file.read(reinterpret_cast<char*>(data), max_size);
    *read_data = file.gcount();
    return true;
  };

  req.form_data.push_back(fileItem);

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