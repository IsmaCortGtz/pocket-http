#include <pockethttp/pockethttp.hpp>
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <METHOD> <URL>" << std::endl;
        return 1;
    }

    pockethttp::Http https;
    

    pockethttp::Request request;
    request.method = argv[1]; // HTTP Method (GET, POST, etc.)
    request.url = argv[2]; // Full URL (example: http://example.com/path)

    try {
        pockethttp::Response response;
        std::string bodyString;
        bool firstChunk = true;

            https.request(request, [&response, &bodyString, &firstChunk](const pockethttp::Response& res, const std::vector<uint8_t>& chunk) {
                if (firstChunk) {
                    response = res;
                    firstChunk = false;
                    
                    std::string contentLength = res.headers.get("Content-Length");
                    std::string contentEncoding = res.headers.get("Content-Encoding");
                    bool isCompressed = !contentEncoding.empty() && 
                                    (contentEncoding.find("gzip") != std::string::npos ||
                                        contentEncoding.find("deflate") != std::string::npos);
                    
                    if (!contentLength.empty() && !isCompressed) bodyString.reserve(std::stoul(contentLength));
                    else if (isCompressed) bodyString.reserve(16384);
                    else bodyString.reserve(8192);
                }
                
                bodyString.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                return true;
            });
        
        
        std::cout << response.version << " " << response.status << " " << response.statusText << std::endl;
        std::cout << response.headers.dump() << std::endl << bodyString << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}