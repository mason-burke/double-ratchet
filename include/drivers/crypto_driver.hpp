#pragma once

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/files.h>
#include <crypto++/hex.h>
#include <crypto++/hkdf.h>
#include <crypto++/hmac.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rijndael.h>
#include <crypto++/sha.h>

#include "../../include-shared/messages.hpp"

using namespace CryptoPP;

class CryptoDriver {
public:
  DHParams_Message DH_generate_params();
  std::tuple<DH, SecByteBlock, SecByteBlock>
  DH_initialize(const DHParams_Message &DH_params);
  SecByteBlock
  DH_generate_shared_key(const DH &DH_obj, const SecByteBlock &DH_private_value,
                         const SecByteBlock &DH_other_public_value);

  SecByteBlock AES_generate_key(const SecByteBlock &DH_shared_key);
  std::string encrypt_and_tag(SecByteBlock mk, std::string plaintext, std::string associated_data);
  std::string decrypt_and_verify(SecByteBlock mk, std::string ciphertext, std::string associated_data);

  SecByteBlock HMAC_generate_key(const SecByteBlock &DH_shared_key);
  std::string HMAC_generate(SecByteBlock key, std::string ciphertext);
  bool HMAC_verify(SecByteBlock key, std::string ciphertext, std::string hmac);

  std::pair<SecByteBlock, SecByteBlock> CryptoDriver::KDF_RK(SecByteBlock rk, SecByteBlock dh_shared_key);
  std::pair<SecByteBlock, SecByteBlock> CryptoDriver::KDF_CK(SecByteBlock ck);

  SecByteBlock make_header(std::pair<SecByteBlock, SecByteBlock> dh_pair, CryptoPP::Integer pn, CryptoPP::Integer n);
  SecByteBlock concat_ad_header(SecByteBlock ad, SecByteBlock header);
};
