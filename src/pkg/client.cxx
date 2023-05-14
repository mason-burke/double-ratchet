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
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call DH_generate_shared_key
 * 2) Use the resulting key in AES_generate_key and HMAC_generate_key
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value) {
  CryptoPP::SecByteBlock sharedKey = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
  this->AES_key = this->crypto_driver->AES_generate_key(sharedKey);
  this->HMAC_key = this->crypto_driver->HMAC_generate_key(sharedKey);
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

  if (this->DH_switched) {
    std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> initResult = this->crypto_driver->DH_initialize(this->DH_params);
    CryptoPP::DH dh_obj = std::get<0>(initResult);
    CryptoPP::SecByteBlock sk = std::get<1>(initResult);
    CryptoPP::SecByteBlock pk = std::get<2>(initResult);

    this->prepare_keys(dh_obj, sk, this->DH_last_other_public_value);
    this->DH_current_private_value = sk;
    this->DH_current_public_value = pk;
    this->DH_switched = false;
  }

  std::pair<std::string, CryptoPP::SecByteBlock> result = this->crypto_driver->AES_encrypt(this->AES_key, plaintext);
  std::string ciphertext = result.first;
  CryptoPP::SecByteBlock iv = result.second;

  std::string mac = this->crypto_driver->HMAC_generate(this->HMAC_key, concat_msg_fields(iv, this->DH_current_public_value, ciphertext));

  Message_Message msg;
  msg.iv = iv;
  msg.public_value = this->DH_current_public_value;
  msg.ciphertext = ciphertext;
  msg.mac = mac;

  return msg;
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

  if (ciphertext.public_value != this->DH_last_other_public_value) { // || !this->DH_switched
    std::tuple<CryptoPP::DH, CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> initResult = this->crypto_driver->DH_initialize(this->DH_params);
    CryptoPP::DH dh_obj = std::get<0>(initResult);
    this->prepare_keys(dh_obj, this->DH_current_private_value, ciphertext.public_value);
    this->DH_last_other_public_value = ciphertext.public_value;
    this->DH_switched = true;
  }

  std::string decrypted = this->crypto_driver->AES_decrypt(this->AES_key, ciphertext.iv, ciphertext.ciphertext);
  bool authentic = this->crypto_driver->HMAC_verify(this->HMAC_key, concat_msg_fields(ciphertext.iv, ciphertext.public_value, ciphertext.ciphertext), ciphertext.mac);

  return std::pair<std::string, bool>(decrypted, authentic);
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
  
  this->prepare_keys(dh_obj, sk, opvm.public_value);
  this->DH_params = dhParams;
  this->DH_switched = true;
  this->DH_current_private_value = sk;
  this->DH_current_public_value = pk;
  this->DH_last_other_public_value = opvm.public_value;
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
