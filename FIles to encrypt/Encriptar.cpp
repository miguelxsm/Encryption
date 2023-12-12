#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
using namespace std;
using namespace CryptoPP;

string EncryptRSA(const string& plain, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    string cipher;
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource ss1(plain, true, new PK_EncryptorFilter(rng, e, new StringSink(cipher)));
    return cipher;
}


string EncryptAES(const string& plain, const SecByteBlock& key, const SecByteBlock& iv) {
    string cipher;
    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), iv);

        StringSource ss(plain, true,
            new StreamTransformationFilter(encryption,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const CryptoPP::Exception& ex) {
        cerr << ex.what() << endl;
        exit(1);
    }

    return cipher;
}

int main() {
    AutoSeededRandomPool rng;

    // RSA Key Generation
    InvertibleRSAFunction rsaParams;
    rsaParams.GenerateRandomWithKeySize(rng, 2048);
    RSA::PrivateKey rsaPrivateKey(rsaParams);
    RSA::PublicKey rsaPublicKey(rsaParams);

    // ECC Key Generation for ECDH
    ECDH<ECP>::Domain dhDomain(ASN1::secp256r1());
    SecByteBlock privKey(dhDomain.PrivateKeyLength()), pubKey(dhDomain.PublicKeyLength());
    dhDomain.GenerateKeyPair(rng, privKey, pubKey);

    // Simulate ECDH key agreement
    SecByteBlock sharedKey(dhDomain.AgreedValueLength());
    // You would normally obtain the peer's public key from the peer
    // Here we're just demonstrating with our own keys
    if(!dhDomain.Agree(sharedKey, privKey, pubKey)) {
        throw runtime_error("Failed to agree on a shared key");
    }

// Generate AES key and IV
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH), iv(AES::BLOCKSIZE);
    rng.GenerateBlock(aesKey, aesKey.size());
    rng.GenerateBlock(iv, iv.size());

    // Encrypt the AES key with RSA
    string encodedAESKey;
    encodedAESKey = EncryptRSA(string(reinterpret_cast<const char*>(aesKey.BytePtr()), aesKey.size()), rsaPublicKey);


    ifstream inputFile("entrada.txt");
    ofstream outputFile("salida.txt");

    if (!inputFile.is_open()) {
        cerr << "No se pudo abrir los archivos." << endl;
        return 1;
    }

    // RSA Encryption
   string inputLine, encryptedText, resultRSA;
   resultRSA = "";
    auto startRSA = chrono::high_resolution_clock::now();
    while (getline(inputFile, inputLine)) {
        encryptedText = EncryptAES(inputLine, aesKey, iv);
        resultRSA += encryptedText + "\n";
    }
    auto endRSA = chrono::high_resolution_clock::now();
    inputFile.close();
    inputFile.open("entrada.txt");
    inputFile.clear();

    // Verificar si el archivo se abrió correctamente después de volver a abrirlo
    if (!inputFile.is_open()) {
        cerr << "No se pudo volver a abrir el archivo de entrada para ElGamal." << endl;
        return 1;
    }
    // ElGamal Encryption
    string result2;
    result2 = "";
    encryptedText = "";
    auto startECC = chrono::high_resolution_clock::now();
    while (getline(inputFile, inputLine)) {
        encryptedText = EncryptAES(inputLine, aesKey, iv);
        result2 += encryptedText + "\n";
    }
    auto endECC = chrono::high_resolution_clock::now();

    // Calculating elapsed time
    chrono::duration<double, milli> rsaTime = endRSA - startRSA;
    chrono::duration<double, milli> ECCtime = endECC - startECC;

    // Write results to file
    outputFile << "Texto encriptado con RSA: " << resultRSA << endl;
    outputFile << "Texto encriptado con ECC(ECDH + AES): " << result2 << endl;
    outputFile << "Tiempo de encriptación RSA: " << rsaTime.count() << " ms" << endl;
    outputFile << "Tiempo de encriptación ElGamal: " << ECCtime.count() << " ms" << endl;

    cout << "RSA Encryption Time: " << rsaTime.count() << " ms" << endl;
    cout << "ECC Encryption Time: " << ECCtime.count() << " ms" << endl;

    inputFile.close();
    outputFile.close();

    return 0;
}
