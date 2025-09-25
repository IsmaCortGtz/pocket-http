#include <pockethttp/pockethttp.hpp>
#include <iostream>

int main (int argc, char* argv[]) {
#ifdef USE_POCKET_HTTP_BEARSSL
  pockethttp::SystemCerts::init();
  std::cout << std::endl << "Loaded " << pockethttp::SystemCerts::getCertsSize() << " certificates." << std::endl;
#endif // USE_POCKET_HTTP_BEARSSL
  
  return 0;
}