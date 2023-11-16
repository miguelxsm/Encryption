#include <iostream>
#include <string>
#include <cryptopp/dsa.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <string>

using namespace std;
using namespace CryptoPP;

string rsaEncrypt(const string& publicKeyStr, const string& plainText) {
    AutoSeededRandomPool rng;

    // Convertir la clave pública de string a formato RSA
    RSA::PublicKey publicKey;
    StringSource ss(publicKeyStr, true, new Base64Decoder);
    publicKey.BERDecode(ss);

    // Encriptar
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    string cipherText;
    StringSource(plainText, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(cipherText)
        ) // PK_EncryptorFilter
    ); // StringSource

    return cipherText;
}

string dsaSign(const string& privateKeyStr, const string& message) {
    AutoSeededRandomPool rng;

    // Convertir la clave privada de string a formato DSA
    DSA::PrivateKey privateKey;
    StringSource ss(privateKeyStr, true, new Base64Decoder);
    privateKey.BERDecodePrivateKey(ss, false, ss.MaxRetrievable());

    // Firmar
    DSA::Signer signer(privateKey);
    string signature;
    StringSource(message, true,
        new SignerFilter(rng, signer,
            new StringSink(signature)
        ) // SignerFilter
    ); // StringSource

    return signature;
}


