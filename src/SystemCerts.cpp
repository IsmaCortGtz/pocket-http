#include "pockethttp/SystemCerts.hpp"
#include "pockethttp/Logs.hpp"
#include "pockethttp/Buffer.hpp"

#include "pockethttp/Sockets/certs.hpp"

#ifdef USE_POCKET_HTTP_BEARSSL
  #if __has_include("bearssl.h")
    #include <bearssl.h>
  #elif __has_include("bearssl/bearssl.h")
    #include <bearssl/bearssl.h>
  #else
    #error "Cannot find bearssl.h or bearssl/bearssl.h"
  #endif
#endif // USE_POCKET_HTTP_BEARSSL

#include <base64/base64.hpp>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <cstdlib>

#if defined(_WIN32)
  #include <windows.h>
  #include <wincrypt.h>
  #pragma comment(lib, "crypt32.lib")
#elif defined(__APPLE__)
  #include <Security/Security.h>
  #include <CoreFoundation/CoreFoundation.h>
#endif


#if defined(__linux__) || defined(__FreeBSD__)
const std::string SYSTEM_CERTS_PATH_LINUX[] = {
    "/etc/ssl/certs/ca-certificates.crt",               // Debian / Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",                 // RHEL / CentOS / Fedora
    "/etc/ssl/ca-bundle.pem",                           // SUSE
    "/usr/share/pki/trust/anchors/ca-bundle.pem",       // SUSE variants
    "/usr/local/share/certs/ca-root-nss.crt",           // FreeBSD
    "/usr/share/ssl/certs/ca-bundle.crt",               // Old Linux fallback
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem", // Arch / Debian fallback
    "/etc/ssl/ca-bundle.trust.crt",                     // SUSE fallback
    "/etc/ssl/cert.pem"                                 // Alpine / Debian fallback
};
#endif

namespace pockethttp {

  namespace Certificates {

    std::vector<std::vector<unsigned char>> pem2Der(const std::string &pem) {
      std::vector<std::vector<unsigned char>> der_list;
      size_t pos = 0;

      while ((pos = pem.find("-----BEGIN CERTIFICATE-----", pos)) != std::string::npos) {
        size_t end = pem.find("-----END CERTIFICATE-----", pos);
        if (end == std::string::npos) break;

        size_t b64_start = pos + strlen("-----BEGIN CERTIFICATE-----");
        std::string b64_block = pem.substr(b64_start, end - b64_start);

        // Eliminar cualquier carácter que no sea Base64
        b64_block.erase(
          std::remove_if(b64_block.begin(), b64_block.end(),
          [](char c){ return !isalnum(c) && c != '+' && c != '/' && c != '='; }),
          b64_block.end()
        );

        // Decodificar Base64
        std::string decoded = base64::from_base64(b64_block);
        std::vector<unsigned char> der(decoded.begin(), decoded.end());
        pos = end + strlen("-----END CERTIFICATE-----");
        if (der.empty() || !isDER(der)) {
          pockethttp_error("[SystemCerts] Failed to decode PEM certificate.");
          continue;
        }

        der_list.push_back(der);
      }

      return der_list;
    }

    bool isDER(std::vector<unsigned char>& cert) {
      unsigned char* buf = cert.data();
      int fb;
      size_t dlen, len = cert.size();

      if (len < 2) return false;
      if (*buf++ != 0x30) return false;

      fb = *buf++;
      len -= 2;
      if (fb < 0x80) {
        return (size_t)fb == len;
      } else if (fb == 0x80) {
        return false;
      } else {
        fb -= 0x80;
        if (len < (size_t)fb + 2) return false;

        len -= (size_t)fb;
        dlen = 0;
        while (fb-- > 0) {
          if (dlen > (len >> 8)) return false;
          dlen = (dlen << 8) + (size_t)*buf++;
        }
        return dlen == len;
      }
    }

    #ifdef USE_POCKET_HTTP_BEARSSL
      void dn_append(void *ctx, const void *data, size_t len) {
        auto vector = static_cast<std::vector<unsigned char>*>(ctx);
        vector->insert(
          vector->end(), 
          static_cast<const unsigned char*>(data), 
          static_cast<const unsigned char*>(data) + len
        );
      }

      bool der2Anchor(const std::vector<unsigned char>& der, br_x509_trust_anchor *ta) {
        br_x509_decoder_context dc;
        br_x509_pkey *pk;
        std::vector<unsigned char> dn_buf;

        br_x509_decoder_init(&dc, dn_append, &dn_buf);
        br_x509_decoder_push(&dc, der.data(), der.size());
        pk = br_x509_decoder_get_pkey(&dc);

        if (!pk) {
          pockethttp_error("[SystemCerts] Failed to decode certificate.");
          return false;
        }

        ta->dn.data = (unsigned char*)malloc(dn_buf.size());
        if (!ta->dn.data) {
          pockethttp_error("[SystemCerts] Memory allocation failed.");
          return false;
        }

        std::memcpy(ta->dn.data, dn_buf.data(), dn_buf.size());
        ta->dn.len = dn_buf.size();
        dn_buf.clear();

        ta->flags = 0;
        if (br_x509_decoder_isCA(&dc)) ta->flags |= BR_X509_TA_CA;
        
        switch (pk->key_type) {
          case BR_KEYTYPE_RSA:
            ta->pkey.key_type = BR_KEYTYPE_RSA;

            ta->pkey.key.rsa.n = (unsigned char*)malloc(pk->key.rsa.nlen);
            if (!ta->pkey.key.rsa.n) {
              pockethttp_error("[SystemCerts] Memory allocation failed.");
              free(ta->dn.data);
              return false;
            }
            std::memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);

            ta->pkey.key.rsa.e = (unsigned char*)malloc(pk->key.rsa.elen);
            if (!ta->pkey.key.rsa.e) {
              pockethttp_error("[SystemCerts] Memory allocation failed.");
              free(ta->dn.data);
              free(ta->pkey.key.rsa.n);
              return false;
            }
            std::memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);

            ta->pkey.key.rsa.elen = pk->key.rsa.elen;
            break;

          case BR_KEYTYPE_EC:
            ta->pkey.key_type = BR_KEYTYPE_EC;
            ta->pkey.key.ec.curve = pk->key.ec.curve;
            ta->pkey.key.ec.q = (unsigned char*)malloc(pk->key.ec.qlen);
            if (!ta->pkey.key.ec.q) {
              pockethttp_error("[SystemCerts] Memory allocation failed.");
              free(ta->dn.data);
              return false;
            }
            std::memcpy(ta->pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
            ta->pkey.key.ec.qlen = pk->key.ec.qlen;
            break;

          default:
            pockethttp_error("[SystemCerts] Unsupported public key type in CA.");
            free(ta->dn.data);
            return false;
        }

        return true;
      }
    #endif // USE_POCKET_HTTP_BEARSSL

  } // namespace Certificates

  // Public
  std::vector<std::vector<unsigned char>> SystemCerts::loadSystemCerts() {
    std::vector<std::vector<unsigned char>> der_list;

    #if defined(_WIN32)
      
      pockethttp_log("[SystemCerts] Loading system CA certificates for Windows.");
      HCERTSTORE hStore = CertOpenSystemStoreW(NULL, L"ROOT");
      if (!hStore) {
        pockethttp_error("[SystemCerts] Failed to open ROOT certificate store.");
        return {};
      }

      PCCERT_CONTEXT pCertContext = nullptr;
      while ((pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) != nullptr) {
        std::vector<unsigned char> certBuf(
            pCertContext->pbCertEncoded,
            pCertContext->pbCertEncoded + pCertContext->cbCertEncoded
        );

        if (certBuf.empty() || !pockethttp::Certificates::isDER(certBuf)) {
          pockethttp_error("[SystemCerts] Invalid DER certificate found, skipping.");
          continue;
        }

        der_list.push_back(std::move(certBuf));
      }
      
      CertCloseStore(hStore, 0);
    
    #elif defined(__APPLE__)

      pockethttp_log("[SystemCerts] Loading system CA certificates for macOS.");
      auto loadFromKeychain = [&](SecKeychainRef keychain) {
        CFArrayRef searchList = CFArrayCreate(nullptr, (const void **)&keychain, 1, &kCFTypeArrayCallBacks);

        const void *keys[]   = { kSecClass, kSecReturnRef, kSecMatchLimit, kSecMatchSearchList };
        const void *values[] = { kSecClassCertificate, kCFBooleanTrue, kSecMatchLimitAll, searchList };

        CFDictionaryRef query = CFDictionaryCreate(nullptr, keys, values, 4,
                                                   &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        CFArrayRef certsArray = nullptr;
        OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&certsArray);
        CFRelease(query);
        CFRelease(searchList);

        if (status != errSecSuccess || !certsArray) {
          pockethttp_error("[SystemCerts] Failed to retrieve certificates from current keychain.");
          return;
        }

        CFIndex count = CFArrayGetCount(certsArray);
        for (CFIndex i = 0; i < count; i++) {
          SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certsArray, i);
          if (!cert) continue;

          CFDataRef certData = SecCertificateCopyData(cert);
          if (!certData) continue;

          const UInt8 *bytes = CFDataGetBytePtr(certData);
          CFIndex len = CFDataGetLength(certData);
          std::vector<unsigned char> buf(bytes, bytes + len);

          if (buf.empty() || !pockethttp::Certificates::isDER(buf)) {
            pockethttp_error("[SystemCerts] Invalid DER certificate found, skipping.");
            continue;
          }

          der_list.push_back(std::move(buf));
          CFRelease(certData);
        }

        CFRelease(certsArray);
      };
    
      // System Roots from Apple
      SecKeychainRef rootsKeychain = nullptr;
      if (SecKeychainOpen("/System/Library/Keychains/SystemRootCertificates.keychain", &rootsKeychain) == errSecSuccess) {
        pockethttp_log("[SystemCerts] Loading from SystemRootCertificates.keychain");
        loadFromKeychain(rootsKeychain);
        CFRelease(rootsKeychain);
      }

      // System Keychain (CA installed by the system administrator)
      SecKeychainRef systemKC = nullptr;
      if (SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &systemKC) == errSecSuccess) {
        pockethttp_log("[SystemCerts] Loading from System Keychain");
        loadFromKeychain(systemKC);
        CFRelease(systemKC);
      }

      // Login Keychain (current user)
      SecKeychainRef loginKC = nullptr;
      if (SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &loginKC) == errSecSuccess) {
        pockethttp_log("[SystemCerts] Loading from Login Keychain");
        loadFromKeychain(loginKC);
        CFRelease(loginKC);
      }

    #elif defined(__linux__) || defined(__FreeBSD__)
      
      pockethttp_log("[SystemCerts] Loading system CA certificates for Linux/FreeBSD.");
        
      for (const auto& path : SYSTEM_CERTS_PATH_LINUX) {
        std::ifstream file(path);
        if (file.fail()) continue;

        pockethttp_log("[SystemCerts] Found certificate file: " << path);
        std::string pem((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        std::vector<std::vector<unsigned char>> der_certs = pockethttp::Certificates::pem2Der(pem);
        if (der_certs.empty()) {
          pockethttp_log("[SystemCerts] No valid PEM certificates found in: " << path);
          continue;
        }

        for (auto& der : der_certs) {
          if (der.empty() || !pockethttp::Certificates::isDER(der)) {
            pockethttp_error("[SystemCerts] Invalid DER certificate found, skipping.");
            continue;
          }

          der_list.push_back(std::move(der));
        }

        break;
      }

    #else

      pockethttp_error("[SystemCerts] System certificate loading not implemented for this OS.");
      return {};

    #endif
    
    pockethttp_log("[SystemCerts] Loaded " << der_list.size() << " CA certificates from the system.");
    return der_list;
  }
    
  #ifdef USE_POCKET_HTTP_BEARSSL
    bool SystemCerts::initialized = false;
    std::vector<br_x509_trust_anchor> SystemCerts::certs;

    br_x509_trust_anchor* SystemCerts::getBearSSLTrustAnchors() {
      if (!initialized) SystemCerts::init();
      return certs.data();
    }

    size_t SystemCerts::getBearSSLTrustAnchorsSize() {
      if (!initialized) SystemCerts::init();
      return certs.size();
    }

    void SystemCerts::cleanup() {
      #ifdef USE_POCKET_HTTP_MOZILLA_ROOT_CERTS
        int end = static_cast<int>(certs.size() - TAs_NUM);
      #else
        int end = static_cast<int>(certs.size());
      #endif

      if (end <= 0) return;
      pockethttp_log("[SystemCerts] Cleaning up " << end << " loaded CA certificates.");

      for (int i = 0; i < end; ++i) {
        br_x509_trust_anchor &ta = certs[i];

        free(ta.dn.data);
        if (ta.pkey.key_type == BR_KEYTYPE_RSA) {
          free(ta.pkey.key.rsa.n);
          free(ta.pkey.key.rsa.e);
        } else if (ta.pkey.key_type == BR_KEYTYPE_EC) {
          free(ta.pkey.key.ec.q);
        }
      }
    }

    void SystemCerts::init() {
      if (!certs.empty() || initialized) {
        pockethttp_log("[SystemCerts] Certificates already loaded.");
        return;
      }

      initialized = true;
      std::atexit(pockethttp::SystemCerts::cleanup);

      std::vector<std::vector<unsigned char>> der_list = loadSystemCerts();
      if (der_list.empty()) {
        pockethttp_log("[SystemCerts] No system certificates loaded.");
      } else {
        for (auto& der : der_list) {
          br_x509_trust_anchor ta;
          if (!pockethttp::Certificates::der2Anchor(der, &ta)) {
            pockethttp_error("[SystemCerts] Failed to convert a certificate to BearSSL format, skipping.");
            continue;
          }

          certs.push_back(ta);
        }
        pockethttp_log("[SystemCerts] Successfully loaded " << certs.size() << " BearSSL trust anchors.");
      }

      #ifdef USE_POCKET_HTTP_MOZILLA_ROOT_CERTS
        // Load Mozilla's root CA certificates
        pockethttp_log("[SystemCerts] Loading " << TAs_NUM << " Mozilla's root CA certificates.");
        certs.insert(certs.end(), TAs, TAs + TAs_NUM);
      #endif
    }
  #endif // USE_POCKET_HTTP_BEARSSL

} // namespace pockethttp