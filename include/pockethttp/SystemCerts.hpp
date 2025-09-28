#ifndef POCKET_HTTP_SYSTEM_CERTS_HPP
#define POCKET_HTTP_SYSTEM_CERTS_HPP

#ifdef USE_POCKET_HTTP_BEARSSL
  #if __has_include("bearssl.h")
    #include <bearssl.h>
  #elif __has_include("bearssl/bearssl.h")
    #include <bearssl/bearssl.h>
  #else
    #error "Cannot find bearssl.h or bearssl/bearssl.h"
  #endif
#endif // USE_POCKET_HTTP_BEARSSL

#include <string>
#include <vector>


namespace pockethttp {

  class SystemCerts {
    public:
      static std::vector<std::vector<unsigned char>> loadSystemCerts();
      #ifdef USE_POCKET_HTTP_BEARSSL
        static br_x509_trust_anchor* getBearSSLTrustAnchors();
        static size_t getBearSSLTrustAnchorsSize();
        static void init();
        static void cleanup();
      #endif // USE_POCKET_HTTP_BEARSSL
      
    private:
      #ifdef USE_POCKET_HTTP_BEARSSL
        static bool initialized;
        static std::vector<br_x509_trust_anchor> certs;
      #endif // USE_POCKET_HTTP_BEARSSL
  };

  namespace Certificates {

    
    std::vector<std::vector<unsigned char>> pem2Der(const std::string &pem);
    bool isDER(std::vector<unsigned char>& cert);
    
    #ifdef USE_POCKET_HTTP_BEARSSL
      void dn_append(void *ctx, const void *data, size_t len);
      bool der2Anchor(const std::vector<unsigned char>& der, br_x509_trust_anchor *ta);
    #endif // USE_POCKET_HTTP_BEARSSL

  } // namespace Certificates

} // namespace pockethttp

#endif // POCKET_HTTP_SYSTEM_CERTS_HPP