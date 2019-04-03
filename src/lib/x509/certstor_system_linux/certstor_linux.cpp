/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2019      Patrick Schmidt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/build.h>

#include <algorithm>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/certstor_linux.h>
#include <botan/data_src.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/pem.h>
#include <botan/x509_dn.h>

namespace Botan {

/**
 * Internal class implementation (i.e. Pimpl) to keep the required platform-
 * dependent members of Certificate_Store_Linux contained in this compilation
 * unit.
 */
class Certificate_Store_Linux_Impl
   {
   private:
      static constexpr const char* default_system_store =
         BOTAN_LINUX_CERTSTORE_DEFAULT_FILE;

   public:
      Certificate_Store_Linux_Impl(const std::string& system_store = default_system_store) :
         m_system_store(system_store)
         {
         DataSource_Stream file(m_system_store);
         for(const secure_vector<uint8_t> der : PEM_Code::decode_all(file))
            {
            m_certificates.push_back(std::make_shared<X509_Certificate>(der.data(), der.size()));
            }
         }

   public:
      const std::string m_system_store;
      std::vector<std::shared_ptr<const X509_Certificate>> m_certificates;
   };

Certificate_Store_Linux::Certificate_Store_Linux() :
   m_impl(std::make_shared<Certificate_Store_Linux_Impl>())
   {
   }

Certificate_Store_Linux::Certificate_Store_Linux(const std::string& file) :
   m_impl(std::make_shared<Certificate_Store_Linux_Impl>(file))
   {
   }

std::vector<X509_DN> Certificate_Store_Linux::all_subjects() const
   {
   std::vector<X509_DN> dns;
   std::transform(m_impl->m_certificates.cbegin(), m_impl->m_certificates.cend(),
   std::back_inserter(dns), [](std::shared_ptr<const X509_Certificate> cert) { return cert->subject_dn();});

   return  dns;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_Linux::find_cert(const X509_DN& subject_dn,
                                   const std::vector<uint8_t>& key_id) const
   {
   const auto found_cert = std::find_if(m_impl->m_certificates.cbegin(), m_impl->m_certificates.cend(),
                                        [&](std::shared_ptr<const X509_Certificate> cert)
      {
      if(!key_id.empty() && !cert->subject_key_id().empty())
         {
         return key_id == cert->subject_key_id() &&
                subject_dn == cert->subject_dn();
         }
      return subject_dn == cert->subject_dn();
      });

   if(found_cert != m_impl->m_certificates.cend())
      {
      return *found_cert;
      }

   return nullptr;
   }

std::vector<std::shared_ptr<const X509_Certificate>> Certificate_Store_Linux::find_all_certs(
         const X509_DN& subject_dn,
         const std::vector<uint8_t>& key_id) const
   {
   std::vector<std::shared_ptr<const X509_Certificate>> filtered_certificates;

   std::copy_if(m_impl->m_certificates.cbegin(), m_impl->m_certificates.cend(), std::back_inserter(filtered_certificates),
                [&](std::shared_ptr<const X509_Certificate> cert)
      {
      if(!key_id.empty() && !cert->subject_key_id().empty())
         {
         return key_id == cert->subject_key_id() &&
                subject_dn == cert->subject_dn();
         }
      return subject_dn == cert->subject_dn();
      });

   return filtered_certificates;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_Linux::find_cert_by_pubkey_sha1(const std::vector<uint8_t>& key_hash) const
   {
   if(key_hash.size() != 20)
      {
      throw Invalid_Argument("Certificate_Store_Linux::find_cert_by_pubkey_sha1 invalid hash");
      }

   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-1"));

   const auto found_cert = std::find_if(m_impl->m_certificates.cbegin(), m_impl->m_certificates.cend(),
                                        [&](std::shared_ptr<const X509_Certificate> cert)
      {
      hash->update(cert->subject_public_key_bitstring());
      if(key_hash == hash->final_stdvec()) //final_stdvec also clears the hash to initial state
         {
         return true;
         }
      return false;
      });

   if(found_cert != m_impl->m_certificates.cend())
      {
      return *found_cert;
      }

   return nullptr;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_Linux::find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const
   {
   BOTAN_UNUSED(subject_hash);
   throw Not_Implemented("Certificate_Store_Linux::find_cert_by_raw_subject_dn_sha256");
   }

std::shared_ptr<const X509_CRL> Certificate_Store_Linux::find_crl_for(const X509_Certificate& subject) const
   {
   BOTAN_UNUSED(subject);
   return {};
   }

}
