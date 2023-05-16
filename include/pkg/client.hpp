#pragma once

#include <iostream>
#include <mutex>
#include <map>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class Client {
public:
  Client(std::shared_ptr<NetworkDriver> network_driver,
         std::shared_ptr<CryptoDriver> crypto_driver);
  Message_Message send(std::string plaintext);
  std::pair<std::string, bool> receive(Message_Message ciphertext);
  void run(std::string command);
  void HandleKeyExchange(std::string command);
  std::pair<std::string, bool> try_skipped_message_keys(Message_Message ciphertext);
  void skip_message_keys(CryptoPP::Integer until);
  void dh_ratchet(Header header);

private:
  void ReceiveThread();
  void SendThread();

  std::mutex mtx;

  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  // DH Fields
  DHParams_Message DH_params;

  // Double Ratchet
  // ratchet keypair (sending/self)
  std::pair<SecByteBlock, SecByteBlock> DHs;
  // ratchet public key (received)
  SecByteBlock DHr;
  // root key
  SecByteBlock RK;
  // chain key for sending
  SecByteBlock CKs;
  // chain key for receiving
  SecByteBlock CKr;
  // message number for sending
  CryptoPP::Integer Ns;
  // message number for sending
  CryptoPP::Integer Nr;
  // number of messages in previous sending chain
  CryptoPP::Integer PN;
  // dictionary of skipped-over message keys, indexed by ratchet public key 
  // and message number. Raises an exception if too many elements are stored.
  // should be double mapping, see 3.2
  std::map<CryptoPP::Integer, SecByteBlock> MK_skipped;
};
