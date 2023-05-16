#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  auto keygen = this->crypto_driver->KDF_CK(this->CKs);
  this->CKs = keygen.first;
  SecByteBlock mk = keygen.second;
  std::string header = this->crypto_driver->make_header(this->DHs, this->PN, this->Ns, "");

  this->Ns += 1;
  // todo: make both into SecByteBlocks (add back in associated data!)
  return this->crypto_driver->encrypt_and_tag(mk, plaintext, header);// + associated_data)
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message ciphertext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  auto attempt_1 = try_skipped_message_keys(ciphertext);
  if (attempt_1.second) {
    return std::pair<std::string, bool>(attempt_1.first, true);
  }

  if (ciphertext.header.DHr != this->DHr) {
    skip_message_keys(ciphertext.header.PN);
    dh_ratchet(ciphertext.header);
  }
  
  skip_message_keys(ciphertext.header.N);

  auto keygen = this->crypto_driver->KDF_CK(this->CKr);
  this->CKs = keygen.first;
  SecByteBlock mk = keygen.second;

  this->Nr += 1;
  return std::make_pair(this->crypto_driver->decrypt_and_verify(mk, ciphertext), true);
}

// see if the message is out of order, and try to decrypt it if possible
std::pair<std::string, bool> Client::try_skipped_message_keys(Message_Message ciphertext) {
  // concat blocks for ease of lookup, surely this won't go wrong
  SecByteBlock map_key = ciphertext.header.DHr + integer_to_byteblock(ciphertext.header.N);
  if (this->MK_skipped.count(map_key) > 0) {
    auto mk = MK_skipped[map_key];
    MK_skipped.erase(map_key);
    return std::make_pair(this->crypto_driver->decrypt_and_verify(mk, ciphertext), true); 
  }
  return std::make_pair("", false);
}

// skip over message keys to catch up to current, storing the old ones in case of out-of-order messages
void Client::skip_message_keys(CryptoPP::Integer until) {
  // max number of skipped messages, pick like 10 for now
  if (this->Nr + 10 < until) {
    throw std::runtime_error("until too high.");
  }

  if (!this->CKr.empty()) {
    while (this->Nr < until) {
      auto keygen = this->crypto_driver->KDF_CK(this->CKr);
      this->CKr = keygen.first;
      this->MK_skipped[this->DHr + integer_to_byteblock(this->Nr)] = keygen.second;
      this->Nr += 1;
    }
  }
}

// ratchet!
void Client::dh_ratchet(Header header) {
  this->PN = this->Ns;
  this->Ns = 0;
  this->Nr = 0;
  this->DHr = header.DHr;
  auto dh_1 = this->crypto_driver->DH_initialize(this->DH_params);
  auto keys_1 = this->crypto_driver->KDF_RK(this->RK, this->crypto_driver->DH_generate_shared_key(std::get<0>(dh_1), this->DHs.first, this->DHr));
  this->RK = keys_1.first;
  this->CKr = keys_1.second;
  auto dh_2 = this->crypto_driver->DH_initialize(this->DH_params);
  this->DHs = std::make_pair(std::get<1>(dh_2), std::get<2>(dh_2));
  auto keys_2 = this->crypto_driver->KDF_RK(this->RK, this->crypto_driver->DH_generate_shared_key(std::get<0>(dh_1), this->DHs.first, this->DHr));
  this->RK = keys_2.first;
  this->CKs = keys_2.second;
}



/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`
 * `command` can be either "listen" or "connect"; the listener should read()
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
  std::vector<unsigned char> paramData;
  DHParams_Message dhParams;

  if (command == "connect") {
    dhParams = this->crypto_driver->DH_generate_params();
    dhParams.serialize(paramData);
    this->network_driver->send(paramData);
  } else if (command == "listen") {
    paramData = this->network_driver->read();
    dhParams.deserialize(paramData);

    this->DHr = SecByteBlock();
    this->CKs = SecByteBlock();

  } else throw std::runtime_error("Unsupported command.");

  std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> initResult = this->crypto_driver->DH_initialize(dhParams);
  CryptoPP::DH dh_obj = std::get<0>(initResult);
  CryptoPP::SecByteBlock sk = std::get<1>(initResult);
  CryptoPP::SecByteBlock pk = std::get<2>(initResult);

  std::vector<unsigned char> myPublicValData;
  PublicValue_Message mpvm;
  mpvm.public_value = pk;
  mpvm.serialize(myPublicValData);

  this->network_driver->send(myPublicValData);
  std::vector<unsigned char> otherPublicValData = this->network_driver->read();

  PublicValue_Message opvm;
  opvm.deserialize(otherPublicValData);
  
  SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(dh_obj, sk, opvm.public_value);

  if (command == "connect") {
    this->DHs = std::make_pair(sk, pk);
    this->DHr = opvm.public_value;

    auto keygen = this->crypto_driver->KDF_RK(shared_key, shared_key);
    this->RK = keygen.first;
    this->CKs = keygen.second;
  } else if (command == "listen") {
    this->DHs = std::make_pair(sk, pk);
    this->RK = shared_key;
  }

  this->CKr = SecByteBlock();
  this->Ns = 0;
  this->Nr = 0;
  this->PN = 0;
  this->MK_skipped = std::map<SecByteBlock, SecByteBlock>();
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}
