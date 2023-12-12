#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
#include <cryptopp/dsa.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

string rsaEncrypt(const RSA::PublicKey& publicKey, const string& plainText, double& elapsedSeconds) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    auto start = chrono::high_resolution_clock::now();
    string cipherText;
    StringSource(plainText, true, new PK_EncryptorFilter(rng, encryptor, new StringSink(cipherText)));
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;
    elapsedSeconds = diff.count();

    return cipherText;
}

string dsaSign(const DSA::PrivateKey& privateKey, const string& message, double& elapsedSeconds) {
    AutoSeededRandomPool rng;
    DSA::Signer signer(privateKey);

    auto start = chrono::high_resolution_clock::now();
    string signature;
    StringSource(message, true, new SignerFilter(rng, signer, new StringSink(signature)));
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;
    elapsedSeconds = diff.count();

    return signature;
}

int main() {
    AutoSeededRandomPool rng;

    // Generar clave privada RSA y su correspondiente clave pública
    InvertibleRSAFunction parametros_rsa;
    parametros_rsa.GenerateRandomWithKeySize(rng, 4096); // Tamaño de clave de 4096 bits
    RSA::PrivateKey privateKeyRSA(parametros_rsa);
    RSA::PublicKey publicKeyRSA(parametros_rsa);

    // Generar clave privada DSA y su correspondiente clave pública
    DSA::PrivateKey privateKeyDSA;
    privateKeyDSA.GenerateRandomWithKeySize(rng, 2048); // Tamaño de clave de 4096 bits
    DSA::PublicKey publicKeyDSA;
    privateKeyDSA.MakePublicKey(publicKeyDSA);

    ifstream inputFile("entrada.txt");
    ofstream outputFile("salida.txt");

    if (!inputFile.is_open() || !outputFile.is_open()) {
        cerr << "No se pudo abrir los archivos." << endl;
        return 1;
    }

    string inputLine, encryptedText, signedText;
    double rsaElapsed = 0.0, dsaElapsed = 0.0;

    while (getline(inputFile, inputLine)) {
        encryptedText = rsaEncrypt(publicKeyRSA, inputLine, rsaElapsed);
        signedText = dsaSign(privateKeyDSA, encryptedText, dsaElapsed);

        outputFile << "Texto Encriptado: " << encryptedText << endl;
        outputFile << "Firma DSA: " << signedText << endl;
        outputFile << "RSA ha tardado " << rsaElapsed << " segundos" << endl;
        outputFile << "DSA ha tardado " << dsaElapsed << " segundos" << endl;
    }

    inputFile.close();
    outputFile.close();
    return 0;
}
