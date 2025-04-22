#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cstdint>

using namespace std;

#define AES_KEYSIZE 16
#define BLOCK_SIZE 16
#define HMAC_KEYSIZE 16

// XOR-based AES-128 ECB encryption (for demonstration only)
void aesEcbEncrypt(const vector<uint8_t>& plaintext, vector<uint8_t>& ciphertext, const vector<uint8_t>& key) {
    ciphertext = plaintext;
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext[i] ^= key[i % AES_KEYSIZE];
    }
}

void aesEcbDecrypt(const vector<uint8_t>& ciphertext, vector<uint8_t>& plaintext, const vector<uint8_t>& key) {
    plaintext = ciphertext;
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        plaintext[i] ^= key[i % AES_KEYSIZE];
    }
}

// Simple SHA-256 simulation using XOR for demo
vector<uint8_t> sha256(const vector<uint8_t>& data) {
    vector<uint8_t> hash(32, 0);
    for (size_t i = 0; i < data.size(); ++i) {
        hash[i % 32] ^= data[i];
    }
    return hash;
}

// HMAC using simulated SHA-256
vector<uint8_t> computeHMAC(const vector<uint8_t>& data, const vector<uint8_t>& key) {
    const size_t blockSize = 64;
    vector<uint8_t> oKeyPad(blockSize, 0x5c);
    vector<uint8_t> iKeyPad(blockSize, 0x36);
    vector<uint8_t> keyPadded = key;

    if (key.size() > blockSize) {
        keyPadded = sha256(key);
    }
    keyPadded.resize(blockSize, 0x00);

    for (size_t i = 0; i < blockSize; ++i) {
        oKeyPad[i] ^= keyPadded[i];
        iKeyPad[i] ^= keyPadded[i];
    }

    vector<uint8_t> inner = iKeyPad;
    inner.insert(inner.end(), data.begin(), data.end());

    vector<uint8_t> innerHash = sha256(inner);
    vector<uint8_t> outer = oKeyPad;
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());

    return sha256(outer);
}

// Simulated RSA Digital Signature
vector<uint8_t> signTransaction(const vector<uint8_t>& data, const vector<uint8_t>& privateKey) {
    vector<uint8_t> input = privateKey;
    input.insert(input.end(), data.begin(), data.end());
    return sha256(input);
}

bool verifySignature(const vector<uint8_t>& data, const vector<uint8_t>& signature, const vector<uint8_t>& publicKey) {
    vector<uint8_t> input = publicKey;
    input.insert(input.end(), data.begin(), data.end());
    vector<uint8_t> expectedSignature = sha256(input);
    return expectedSignature == signature;
}

void inputAESKey(vector<uint8_t>& key, const string& prompt) {
    string userKey;
    cout << prompt;
    getline(cin, userKey);
    if (userKey.size() < AES_KEYSIZE) {
        userKey.append(AES_KEYSIZE - userKey.size(), '0');
    }
    key.assign(userKey.begin(), userKey.begin() + AES_KEYSIZE);
}

void printHex(const vector<uint8_t>& data) {
    for (uint8_t byte : data) {
        cout << hex << setw(2) << setfill('0') << (int)byte;
    }
}

int main() {
    vector<uint8_t> aesKey(AES_KEYSIZE);
    vector<uint8_t> hmacKey(HMAC_KEYSIZE, 0xAB);

    inputAESKey(aesKey, "Enter a 16-character AES key: ");

    string transaction, accountNumber;
    cout << "Enter transaction details: ";
    getline(cin, transaction);
    cout << "Enter account number: ";
    getline(cin, accountNumber);

    string fullMessage = "Transaction: " + transaction + " | Account: " + accountNumber;
    vector<uint8_t> plaintext(fullMessage.begin(), fullMessage.end());

    // Step 1: Encrypt transaction
    vector<uint8_t> ciphertext;
    aesEcbEncrypt(plaintext, ciphertext, aesKey);

    // Step 2: Generate HMAC
    vector<uint8_t> authTag = computeHMAC(ciphertext, hmacKey);

    // Step 3: Simulated RSA Digital Signature
    vector<uint8_t> customerPrivateKey = {'1','2','3','4','5','6','7','8'}; // Same key used for both
    vector<uint8_t> customerPublicKey = customerPrivateKey;

    vector<uint8_t> digitalSignature = signTransaction(ciphertext, customerPrivateKey);

    // Step 4: Verify Signature
    bool isVerified = verifySignature(ciphertext, digitalSignature, customerPublicKey);

    // Output
    cout << "\nEncrypted Transaction (AES - ECB Mode): ";
    printHex(ciphertext);

    cout << "\nAuthentication Tag (HMAC-SHA256): ";
    printHex(authTag);

    cout << "\nDigital Signature (Simulated RSA): ";
    printHex(digitalSignature);

    if (isVerified) {
        cout << "\n\n✅ Signature Verified. Transaction is authentic.\n";
    } else {
        cout << "\n\n❌ Signature Verification Failed! Possible tampering.\n";
    }

    // Decrypt to confirm
    vector<uint8_t> decrypted;
    aesEcbDecrypt(ciphertext, decrypted, aesKey);
    cout << "\nDecrypted Transaction: " << string(decrypted.begin(), decrypted.end()) << endl;

    return 0;
}
