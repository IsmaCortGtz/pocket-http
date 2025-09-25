#ifndef POCKET_HTTP_SYSTEM_CERTS_HPP
#define POCKET_HTTP_SYSTEM_CERTS_HPP

#ifdef USE_POCKET_HTTP_BEARSSL

#include <bearssl/bearssl.h>
#include <string>
#include <vector>


namespace pockethttp {

  class SystemCerts {
    private:
      static bool initialized;
      static std::vector<br_x509_trust_anchor> certs;
      static void loadSystemCerts();

    public:
      // Load system certificates into a set of trust anchors
      static br_x509_trust_anchor* getCerts();
      static size_t getCertsSize();
      static void init();
      static void cleanup();
  };

  namespace Certificates {

    void dn_append(void *ctx, const void *data, size_t len);

    std::vector<std::vector<unsigned char>> pem2Der(const std::string &pem);

    bool isDER(std::vector<unsigned char>& cert);

    bool der2Anchor(const std::vector<unsigned char>& der, br_x509_trust_anchor *ta);

  } // namespace Certificates

} // namespace pockethttp

#endif // USE_POCKET_HTTP_BEARSSL

#endif // POCKET_HTTP_SYSTEM_CERTS_HPP