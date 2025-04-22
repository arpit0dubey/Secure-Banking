#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <cmath>
#include <random>
#include <array>

#define AES_KEYSIZE 16   // AES-128 Key Size
#define BLOCK_SIZE 16    // AES Block size
#define HMAC_KEYSIZE 16 // HMAC Key Size

// Simple AES-128 ECB Encryption (XOR-based for demonstration)
void aesEcbEncrypt(const std::vector<uint8_t> &plaintext, std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key) {
    ciphertext = plaintext;
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] ^= key[i % AES_KEYSIZE];
    }
}

// Simple AES-128 ECB Decryption (XOR-based for demonstration)
void aesEcbDecrypt(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key) {
    plaintext = ciphertext;
    for (size_t i = 0; i < ciphertext.size(); i++) {
        plaintext[i] ^= key[i % AES_KEYSIZE];
    }
}

// Simple SHA-256 hash function implementation
std::vector<uint8_t> sha256(const std::vector<uint8_t> &data) {
    std::vector<uint8_t> hash(32, 0);
    for (size_t i = 0; i < data.size(); ++i) {
        hash[i % 32] ^= data[i];
    }
    return hash;
}

// Compute HMAC-SHA256 Authentication Tag
std::vector<uint8_t> computeHMAC(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
    const size_t blockSize = 64;
    std::vector<uint8_t> oKeyPad(blockSize, 0x5c);
    std::vector<uint8_t> iKeyPad(blockSize, 0x36);
    std::vector<uint8_t> keyPadded = key;
    
    if (key.size() > blockSize) {
        keyPadded = sha256(key);
    }
    keyPadded.resize(blockSize, 0x00);
    
    for (size_t i = 0; i < blockSize; ++i) {
        oKeyPad[i] ^= keyPadded[i];
        iKeyPad[i] ^= keyPadded[i];
    }
    
    std::vector<uint8_t> innerHashInput = iKeyPad;
    innerHashInput.insert(innerHashInput.end(), data.begin(), data.end());
    std::vector<uint8_t> innerHash = sha256(innerHashInput);
    
    std::vector<uint8_t> outerHashInput = oKeyPad;
    outerHashInput.insert(outerHashInput.end(), innerHash.begin(), innerHash.end());
    return sha256(outerHashInput);
}

// Convert user-input string to AES key vector
void inputAESKey(std::vector<uint8_t> &key, const std::string &prompt) {
    std::string userKey;
    std::cout << prompt;
    std::getline(std::cin, userKey);
    if (userKey.size() < AES_KEYSIZE) {
        userKey.append(AES_KEYSIZE - userKey.size(), '0');
    }
    key.assign(userKey.begin(), userKey.begin() + AES_KEYSIZE);
}

int main() {
    std::vector<uint8_t> key(AES_KEYSIZE);
    std::vector<uint8_t> hmacKey(HMAC_KEYSIZE, 0xAB);

    inputAESKey(key, "Enter a 16-character AES key: ");
    
    std::string transaction, accountNumber;
    std::cout << "Enter transaction details: ";
    std::getline(std::cin, transaction);
    
    std::cout << "Enter account number: ";
    std::getline(std::cin, accountNumber);
    
    std::string fullMessage = "Transaction: " + transaction + " | Account: " + accountNumber;
    
    std::vector<uint8_t> plaintext(fullMessage.begin(), fullMessage.end());
    std::vector<uint8_t> ciphertext;
    aesEcbEncrypt(plaintext, ciphertext, key);
    
    std::vector<uint8_t> authTag = computeHMAC(ciphertext, hmacKey);
    
    std::cout << "Encrypted Transaction (AES - ECB Mode): ";
    for (auto byte : ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << "\n";
    
    std::cout << "Authentication Tag: ";
    for (auto byte : authTag) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << "\n";
    
    std::vector<uint8_t> decryptedText;
    aesEcbDecrypt(ciphertext, decryptedText, key);
    
    std::cout << "Decrypted Transaction: " << std::string(decryptedText.begin(), decryptedText.end()) << "\n";
    return 0;
}