#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message CryptoDriver::DH_generate_params() {
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::PrimeAndGenerator pg;
  CryptoPP::Integer p, q, g;
  pg.Generate(1, prng, 512, 511);
  p = pg.Prime();
  q = pg.SubPrime();
  g = pg.Generator();

  DHParams_Message msg;
  msg.p = p;
  msg.q = q;
  msg.g = g;

  return msg;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
CryptoDriver::DH_initialize(const DHParams_Message &DH_params) {
  CryptoPP::DH dh(DH_params.p, DH_params.q, DH_params.g);
  CryptoPP::SecByteBlock sk(dh.PrivateKeyLength());
  CryptoPP::SecByteBlock pk(dh.PublicKeyLength());
  CryptoPP::AutoSeededRandomPool prng;

  dh.GenerateKeyPair(prng, sk, pk);
  return std::tuple<DH, SecByteBlock, SecByteBlock>(dh, sk, pk);
}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw a `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  CryptoPP::SecByteBlock sharedKey(DH_obj.AgreedValueLength());

  bool agreed = DH_obj.Agree(sharedKey, DH_private_value, DH_other_public_value);
  if (!agreed) {
    throw std::runtime_error("Key agreement failure.");
  }

  return sharedKey;
}


/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size AES::BLOCKSIZE
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * `AES_encryptor`.
 * 3) Return ciphertext and iv used in encryption or throw a
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::string CryptoDriver::encrypt_and_tag(SecByteBlock mk, std::string plaintext, std::string associated_data) {
  try {
    CryptoPP::HKDF<SHA256> builder;

    CryptoPP::SecByteBlock keys;
    CryptoPP::SecByteBlock zeros;
    zeros.CleanNew(80);

    builder.DeriveKey(keys, 80, mk, mk.size(), zeros, zeros.size(), nullptr, 0);

    SecByteBlock encryption_key = SecByteBlock(keys.begin(), 32);
    SecByteBlock authentication_key = SecByteBlock(keys.begin() + 32, 32);
    SecByteBlock iv = SecByteBlock(keys.begin() + 64, 16);


    CryptoPP::CBC_Mode<AES>::Encryption AES_encryptor;
    std::string ciphertext;

    AES_encryptor.SetKeyWithIV(encryption_key, encryption_key.size(), iv);
    
    CryptoPP::StringSource ss(plaintext, true,
      new CryptoPP::StreamTransformationFilter(AES_encryptor,
        new CryptoPP::StringSink(ciphertext)
      )
    );

    std::string hmac = HMAC_generate(authentication_key, plaintext + associated_data);

    return ciphertext + hmac;

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using SetKeyWithIV on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using `AES_decryptor`.
 * 3) Return the plaintext or throw a `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::decrypt_and_verify(SecByteBlock mk, std::string ciphertext, std::string associated_data) {
  //todo: rework
  try {
    std::string plaintext;
    CryptoPP::CBC_Mode<AES>::Decryption AES_decryptor;
    
    //todo: figure out iv
    AES_decryptor.SetKeyWithIV(mk, mk.size(), iv);
    StringSource s(ciphertext, true, 
      new StreamTransformationFilter(AES_decryptor,
          new StringSink(plaintext)
      )
    );

    return plaintext;

  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error`upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    CryptoPP::HMAC<SHA256> builder(key, key.size());
    std::string mac;

    StringSource ss(ciphertext, true,
        new HashFilter(builder,
            new StringSink(mac)
        ) 
    );

    return mac;

  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the message through a `HashVerificationFilter` to verify the HMAC.
 * 3) Throw `std::runtime_error`upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  
  CryptoPP::HMAC<SHA256> builder(key, key.size());

  try {
    StringSource(ciphertext + mac, true, 
        new HashVerificationFilter(builder, NULL, flags)
    );
    return true;
  } catch (const CryptoPP::Exception &e) {
    return false;
  }
}

/**
 * @brief Returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF 
 * keyed by a 32-byte root key to a Diffie-Hellman output.
 * @param rk 32-byte root key
 * @param dh_shared_key Diffie-Hellman output //todo: verify that it's the shared key
 * @return pair of root key and chain key
*/
std::pair<SecByteBlock, SecByteBlock> CryptoDriver::KDF_RK(SecByteBlock rk, SecByteBlock dh_shared_key) {
  // todo: verify
  CryptoPP::SecByteBlock keys(64);
  CryptoPP::HKDF<SHA256> builder;
  builder.DeriveKey(keys, AES::DEFAULT_KEYLENGTH, dh_shared_key, dh_shared_key.size(), rk, rk.size(), nullptr, 0);

  return std::pair<SecByteBlock, SecByteBlock>(SecByteBlock(keys.begin(), 16), SecByteBlock(keys.begin() + 16, 16));
}

/**
 * @brief Returns a pair (32-byte chain key, 32-byte message key) as the output of applying
 * a KDF keyed by a 32-byte chain key to some constant.
 * @param ck 32-byte chain key
 * @return pair of chain key and message key
*/
std::pair<SecByteBlock, SecByteBlock> CryptoDriver::KDF_CK(SecByteBlock ck) {
  //todo: verify
  return std::pair<SecByteBlock, SecByteBlock>(string_to_byteblock(HMAC_generate(ck, "1")), string_to_byteblock(HMAC_generate(ck, "2")));
}

/**
 * @brief Creates a new message header containing the DH ratchet public key from the key pair,
 * the previous chain length pn, and the message number n. 
 * @param dh_pair Diffie-Hellman ratchet pair
 * @param pn previous chain length
 * @param n message number
 * @return The returned header object contains ratchet public key dh and integers pn and n.
*/
SecByteBlock make_header(std::pair<SecByteBlock, SecByteBlock> dh_pair, CryptoPP::Integer pn, CryptoPP::Integer n) {
  // todo: write
}

/**
 * @brief Encodes a message header into a parseable byte sequence, prepends the ad byte sequence,
 * and returns the result. If ad is not guaranteed to be a parseable byte sequence, a length value
 * should be prepended to the output to ensure that the output is parseable as a unique pair (ad, header).
 * @param ad ad byte sequence //todo: figure out what this is
 * @param header message header, output of make_header
*/
SecByteBlock concat_ad_header(SecByteBlock ad, SecByteBlock header) {
  // todo: write
}