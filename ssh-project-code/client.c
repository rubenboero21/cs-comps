#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include "client.h"

// openssl libraries (for DH)
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_NEWKEYS 21
#define BLOCKSIZE 64 // if encryption isn't working, check blocksize

// defining global variables to construct the message to hash (H) as part of server verification
// excluding K_S, e, f, & k because we have access to those locally in sendDiffieHellmanExchange()
unsigned char *V_C;
size_t V_C_length;
unsigned char *V_S;
size_t V_S_length;
unsigned char *I_C;
size_t I_C_length;
unsigned char *I_S;
size_t I_S_length;
unsigned char *fGlobal;
size_t fGlobalLen;
unsigned char *eGlobal;
size_t eGlobalLen;
unsigned char *kGlobal;
size_t kGlobalLen;
unsigned char *hashGlobal;
size_t hashGlobalLen;

// remember to free the struct AND data
RawByteArray *constructPacket(RawByteArray *payload) {
    
    // Calculate padding length, calculate packet length, generate random padding, calculate TOTAL packet size
    size_t payloadLength = payload->size;
    
    // + 5 bytes: 4 for packet length, 1 for padding length
    unsigned char paddingLength = BLOCKSIZE - ((payloadLength + 5) % BLOCKSIZE);

    // + 1 for padding length byte: payload size: actual padding bytes
    uint32_t packetLength = htonl(1 + payloadLength + paddingLength);

    RawByteArray *padding = generateRandomBytes(paddingLength);
    
    // size of packet length + size of padding length + size of payload + size of padding 
    size_t totalSize = 4 + 1 + payload -> size + padding -> size;

    RawByteArray *binaryPacket = malloc(sizeof(RawByteArray));
    assert(binaryPacket != NULL);
    binaryPacket -> size = totalSize;
    binaryPacket -> data = malloc(totalSize);
    assert(binaryPacket -> data != NULL);

    // Copy contents into our packet (binaryPacket)
    memcpy(binaryPacket -> data, &packetLength, 4); // length of packet
    memcpy(binaryPacket -> data + 4, &paddingLength, 1); // padding length
    memcpy(binaryPacket -> data + 5, payload -> data, payload -> size); // payload
    memcpy(binaryPacket -> data + 5 + payload -> size, padding -> data, padding -> size); // random padding

    free(padding -> data);
    free(padding);

    return binaryPacket;
}

/*
Extracts and returns the server's public host key (K_S), the server's public DH key (f), and the signature of H (hash(V_C || V_S || I_C || I_S || K_S || e || f || K))
This is hard coded to work for our server response type
Remember to FREE the ServerDHResponse struct and its malloc'ed contents when done
*/
ServerDHResponse *extractServerDHResponse(unsigned char* payload) {
    ServerDHResponse *serverResponse = malloc(sizeof(ServerDHResponse));
    int offset = 10; // packet contents are uniform, so we can jump right to the 9th byte to begin (base 0)

    uint32_t hostKeyTypeLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    serverResponse -> hostKeyTypeLen = hostKeyTypeLen;
    offset += 4;

    unsigned char *hostKeyType = malloc(hostKeyTypeLen);
    // unsigned char *hostKeyTypePtr = hostKeyType; // need to keep a pointer to free later
    memcpy(hostKeyType, payload + offset, hostKeyTypeLen);
    serverResponse -> hostKeyType = hostKeyType;

    // Skip over host key type's bytes
    offset += hostKeyTypeLen;

    uint32_t publicKeyLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    serverResponse -> publicKeyLen = publicKeyLen;
    offset += 4;

    unsigned char *publicKey = malloc(publicKeyLen);
    memcpy(publicKey, payload + offset, publicKeyLen);
    serverResponse -> publicKey = publicKey;
    offset += publicKeyLen;

    uint32_t fLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    serverResponse -> fLen = fLen;
    offset += 4;

    unsigned char *f = malloc(fLen);
    memcpy(f, payload + offset, fLen);
    serverResponse -> f = f;
    offset += fLen;

    uint32_t hostSigLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    serverResponse -> hostSigLen = hostSigLen;
    offset += 4;

    uint32_t hostSigTypeLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    serverResponse -> hostSigTypeLen = hostSigTypeLen;
    offset += 4;

    unsigned char *hostSigType = malloc(hostSigTypeLen);
    memcpy(hostSigType, payload + offset, hostSigTypeLen);
    serverResponse -> hostSigType = hostSigType;
    offset += hostSigTypeLen;

    // size_t hostSigDataLen = hostSigLen - hostSigTypeLen - sizeof(uint32_t);
    uint32_t hostSigDataLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    serverResponse -> hostSigDataLen = hostSigDataLen;
    offset += 4;
    // serverResponse -> hostSigDataLen = hostSigDataLen;

    unsigned char *hostSigData = malloc(hostSigDataLen);
    memcpy(hostSigData, payload + offset, hostSigDataLen);
    serverResponse -> hostSigData = hostSigData;

    return serverResponse;
}

// frees all malloc'ed data from extractServerDHResponse function
void cleanupServerDHResponse(ServerDHResponse *serverResponse) {
    free(serverResponse -> hostKeyType);
    free(serverResponse -> publicKey);
    free(serverResponse -> f);
    free(serverResponse -> hostSigType);
    free(serverResponse -> hostSigData);
    free(serverResponse);
}

// takes in a payload, returns all sections of the payload (Wireshark-esque style)
void printServerDHResponse(unsigned char* payload) {
    int offset = 0;

    uint32_t packetLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("Packet length: %u bytes\n", packetLen);

    int paddingLen = payload[offset];
    offset += 1;
    printf("padding length: %u bytes\n", paddingLen);

    int messageCode = payload[offset];
    offset += 1;
    printf("message code: %i\n", messageCode);
    
    uint32_t hostKeyLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("host key length: %u bytes\n", hostKeyLen);

    uint32_t hostKeyTypeLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("host key type length: %u bytes\n", hostKeyTypeLen);

    unsigned char *hostKeyType = malloc(hostKeyTypeLen + 1); // +1 for null terminator
    memcpy(hostKeyType, payload + offset, hostKeyTypeLen);
    offset += hostKeyTypeLen;
    hostKeyType[hostKeyTypeLen] = '\0';
    printf("host key type: %s\n", hostKeyType);

    uint32_t publicKeyLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("public key length: %u bytes\n", publicKeyLen);

    printf("host public key: ");
    for (int i = 0; i < publicKeyLen; i++) {
        printf("%02x ", payload[offset]);
        offset += 1;
    }
    printf("\n");

    uint32_t mpintLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("mpint length: %u bytes\n", mpintLen);

    printf("f: ");
    for (int i = 0; i < mpintLen; i++) {
        printf("%02x ", payload[offset]);
        offset += 1;
    }
    printf("\n");

    uint32_t hostSigLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("host signature length: %u bytes\n", hostSigLen);

    uint32_t hostSigTypeLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("host signature length: %u bytes\n", hostSigTypeLen);

    // add print of host key signature type after i fix seg fault error from printing above
    unsigned char *hostSigType = malloc(hostSigTypeLen + 1);
    memcpy(hostSigType, payload + offset, hostSigTypeLen);
    offset += hostSigTypeLen;
    hostSigType[hostSigTypeLen] = '\0';
    printf("host key signature type: %s\n", hostSigType);
    
    // this section of the packet is a little weird. host signature length is the length of the 
    // entire section of the packet, host signature type length is the length of the sig type, 
    // but the actual signature data doesn't have a length in the packet, so we need to calculate
    // the length of the entire section (hostSigLen) minus the length of the host signature type 
    // section and the 4 bytes that store the host signature type length 
    int end = offset + hostSigLen - hostSigTypeLen - sizeof(uint32_t);
    printf("host signature data: ");
    while (offset < end) {
        printf("%02x ", payload[offset]);
        offset += 1;
    }
    printf("\n");
}

// Adds the leading 2s complement bit if necessary to ensure that e is positive
// remember to free returned rawbytearray data, and then rawbytearray itself
RawByteArray* addTwosComplementBit(const unsigned char* pub_key, int pub_key_len) {
    int needs_padding = (pub_key[0] & 0x80) != 0;
    int mpint_len = pub_key_len + (needs_padding ? 1 : 0);
    
    unsigned char* mpint = malloc(mpint_len);
    if (needs_padding) {
        mpint[0] = 0x00;
        memcpy(mpint + 1, pub_key, pub_key_len);
    } else {
        memcpy(mpint, pub_key, pub_key_len);
    }
    
    RawByteArray* mpintAndSize = malloc(sizeof(RawByteArray));
    mpintAndSize -> data = mpint;
    mpintAndSize -> size = mpint_len;

    return mpintAndSize;
}

// Function to compute the SHA-256 hash of a message and return it as a pointer to RawByteArray
RawByteArray *computeSHA256Hash(const RawByteArray *inputMessage) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();  // Create a message digest context
    const EVP_MD *md = EVP_sha256();       // Specify the SHA-256 algorithm
    RawByteArray *outputHash = malloc(sizeof(RawByteArray));   // Allocate memory for output struct
    unsigned int hashLength = 0;

    if (mdctx == NULL || outputHash == NULL) {
        printf("Error: Could not create digest context or allocate memory for output hash\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);  // Cleanup if context was allocated
        if (outputHash) free(outputHash);   // Cleanup allocated memory if allocated
        return NULL;
    }

    // Initialize the digest context for SHA-256
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Error: Could not initialize digest\n");
        EVP_MD_CTX_free(mdctx);
        free(outputHash);
        return NULL;
    }

    // Add the input message to be hashed
    if (EVP_DigestUpdate(mdctx, inputMessage->data, inputMessage->size) != 1) {
        printf("Error: Could not update digest\n");
        EVP_MD_CTX_free(mdctx);
        free(outputHash);
        return NULL;
    }

    // Allocate memory for the hash output
    outputHash->data = (unsigned char *)malloc(EVP_MD_size(md));
    if (outputHash->data == NULL) {
        printf("Error: Could not allocate memory for output hash data\n");
        EVP_MD_CTX_free(mdctx);
        free(outputHash);
        return NULL;
    }

    // Finalize the digest and store the result in outputHash->data
    if (EVP_DigestFinal_ex(mdctx, outputHash->data, &hashLength) != 1) {
        printf("Error: Could not finalize digest\n");
        free(outputHash->data);  // Clean up allocated memory in case of failure
        free(outputHash);
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    // Set the size of the output hash
    outputHash->size = hashLength;

    // Clean up
    EVP_MD_CTX_free(mdctx);

    return outputHash;  // Return the pointer to the RawByteArray containing the hash
}

int verifyServerSignature(ServerDHResponse *dhResponse, RawByteArray *message) {
    EVP_PKEY *serverPublicKey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    // Load the server's EDDSA public key from raw byte array (assuming it's Ed25519)
    serverPublicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, dhResponse->publicKey, dhResponse->publicKeyLen);
    if (serverPublicKey == NULL) {
        printf("Error: Could not load server's public key\n");
        goto cleanup;
    }

    // Check for Ed25519 key type
    int keyType = EVP_PKEY_base_id(serverPublicKey);
    if (keyType != EVP_PKEY_ED25519) {
        printf("Error: serverPublicKey is not of type Ed25519\n");
        goto cleanup;
    }

    // Create a digest context for verifying the signature
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error: Could not create digest context\n");
        goto cleanup;
    }

    // Initialize the verification operation for Ed25519 (no digest needed)
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, serverPublicKey) != 1) {
        printf("Error: Could not initialize digest verify operation\n");
        goto cleanup;
    }

    RawByteArray *hashedMessage = computeSHA256Hash(message);
    printf("HASHED MESSAGE:\n");
    for (int i = 0; i < hashedMessage -> size; i++) {
        printf("%02x ", hashedMessage -> data[i]);
    }
    printf("\n");

    // save our hash as a global variable for use in encryption key derivation
    hashGlobal = malloc(hashedMessage -> size);
    hashGlobalLen = hashedMessage -> size;
    memcpy(hashGlobal, hashedMessage -> data, hashGlobalLen);
    

    // Perform the verification using the server's signature (Ed25519 doesn't use DigestUpdate)
    if (EVP_DigestVerify(mdctx, dhResponse->hostSigData, dhResponse->hostSigDataLen, hashedMessage -> data, hashedMessage -> size) == 1) {
        // printf("Server's signature verified successfully!\n");
        ret = 1;  // Signature is valid
    }
    // } else {
    //     printf("Error: Server's signature verification failed\n");
    // }

    free(hashedMessage -> data);
    free(hashedMessage);

cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (serverPublicKey) EVP_PKEY_free(serverPublicKey);

    return ret;
}

// is it weird to only pass in half the variables we need, should we make all the variables we 
// need global?
RawByteArray *concatenateVerificationMessage(unsigned char *keyType, size_t keyTypeLen, unsigned char *pubKey, size_t pubKeyLen, unsigned char *K, size_t K_length) {
    int sum = V_C_length + V_S_length + I_C_length + I_S_length + (sizeof(uint32_t) * 3 + keyTypeLen + pubKeyLen) + eGlobalLen + fGlobalLen + K_length;
    unsigned char *message = malloc(sum);
    int offset = 0;
    memcpy(message, V_C, V_C_length);

    printf("V_C: \n");
    for (int i = offset; i < V_C_length + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
    
    offset += V_C_length;
    memcpy(message + offset, V_S, V_S_length);

    printf("V_S: \n");
    for (int i = offset; i < V_S_length + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
    
    offset += V_S_length;
    memcpy(message + offset, I_C, I_C_length);
    
    printf("I_C: \n");
    for (int i = offset; i < I_C_length + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");
    
    offset += I_C_length;
    memcpy(message + offset, I_S, I_S_length);
    
    printf("I_S: \n");
    for (int i = offset; i < I_S_length + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    offset += I_S_length;

    int temp = offset;
    uint32_t blobLen = htonl(keyTypeLen + pubKeyLen + sizeof(uint32_t) * 2);
    memcpy(message + offset, &blobLen, keyTypeLen + pubKeyLen + sizeof(uint32_t) * 2);
    offset += sizeof(uint32_t);
    
    uint32_t networkKeyTypeLen = htonl(keyTypeLen);
    memcpy(message + offset, &networkKeyTypeLen, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(message + offset, keyType, keyTypeLen);
    offset += keyTypeLen;

    uint32_t networkPubKeyLen = htonl(pubKeyLen);
    memcpy(message + offset, &networkPubKeyLen, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(message + offset, pubKey, pubKeyLen);
    offset += pubKeyLen;

    printf("K_S: \n");
    for (int i = temp; i < offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    memcpy(message + offset, eGlobal, eGlobalLen);

    printf("E: \n");
    for (int i = offset; i < eGlobalLen + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    offset += eGlobalLen;
    memcpy(message + offset, fGlobal, fGlobalLen);

    printf("F: \n");
    for (int i = offset; i < fGlobalLen + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    offset += fGlobalLen;
    memcpy(message + offset, K, K_length);

    printf("K: \n");
    for (int i = offset; i < K_length + offset; i++) {
        printf("%02x ", message[i]);
    }
    printf("\n");

    RawByteArray *messageAndSize = malloc(sizeof(RawByteArray));
    messageAndSize -> data = message;
    messageAndSize -> size = sum;

    return messageAndSize;
}

/*
To get the libraries to work, need to run the following command (on Ruben's arm mac with
openssl installed via homebrew)
gcc client.c -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
gcc <file name> -I<path to openssl install>/include -L<path to openssl install>/lib -lssl -lcrypto
*/
int sendDiffieHellmanExchange(int sock) {
    // generate keys using group 14's p and g
    BIGNUM *p, *g, *f = NULL;
    const BIGNUM *pub_key, *priv_key = NULL;
    RawByteArray *e = NULL, *payload = NULL, *packet = NULL;
    unsigned char *buffer, *serverResponse = NULL;
    unsigned char *kbuf = NULL;
    size_t klen = 0;

    // create group 14 parameters with bignum
    p = BN_new();
    BN_get_rfc3526_prime_2048(p);
    g = BN_new();
    BN_set_word(g, 2);

    DH *dh = DH_new();

    DH_set0_pqg(dh, p, NULL, g);

    DH_set_length(dh, 2048 - 1); // group 14 p is 2048 bits, so our private key (x) should be less than p bits long

    // Print p
    printf("Prime (p): ");
    BN_print_fp(stdout, p);
    printf("\n");

    // Print g
    printf("Generator (g): ");
    BN_print_fp(stdout, g);
    printf("\n");

    DH_generate_key(dh);

    // DH_get0_pqg(dh, &p, &g, NULL);
    DH_get0_key(dh, &pub_key, &priv_key);

    // Print private key
    printf("Private Key (x): ");
    BN_print_fp(stdout, priv_key);
    printf("\n");

    int eSize = BN_num_bytes(pub_key);
    printf("size of e: %i bytes\n", eSize);
    
    // Print private key
    printf("Public Key (e): ");
    BN_print_fp(stdout, pub_key);
    printf("\n");
    
    // e->data = pub_key;
    // e->size = eSize;

    unsigned char* eBytes = malloc(eSize);
    BN_bn2bin(pub_key, eBytes);  
    
    e = addTwosComplementBit(eBytes, eSize);
    // printf("e in Two's Complement: \n");
    // for (int i = 0; i < e -> size; i++) {
    //     printf("%02x ", e->data[i]);
    // }
    // printf("\n");

    // building e payload (including prepending size to mpint)
    buffer = malloc(e -> size + 1 + 4);
    buffer[0] = SSH_MSG_KEXDH_INIT;
    uint32_t mpintLenNetworkOrder = htonl(e->size);
    memcpy(buffer + 1, &mpintLenNetworkOrder, sizeof(uint32_t));
    memcpy(buffer + 5, e -> data, e -> size);

    // store a global copy of e encoded as an mpint for use in message verification
    eGlobal = malloc(e -> size + sizeof(uint32_t));
    memcpy(eGlobal, &mpintLenNetworkOrder, sizeof(uint32_t));
    memcpy(eGlobal + sizeof(uint32_t), e -> data, e -> size);
    eGlobalLen = e -> size + sizeof(uint32_t);

    payload = malloc(sizeof(RawByteArray));
    assert(payload != NULL);

    payload -> data = buffer;
    payload -> size = e -> size + 1 + 4; // +1 for message code, +4 for mpint len

    packet = constructPacket(payload);

    int sentBytes = send(sock, packet -> data, packet -> size, 0);

    if (sentBytes != -1) {
        printf("Successful DH init send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }

    serverResponse = malloc(BUFFER_SIZE);
    memset(serverResponse, 0, BUFFER_SIZE);  // Clear the buffer    
    ssize_t bytesReceived = recv(sock, serverResponse, BUFFER_SIZE, 0);
    
    // looks like the response includes both of the servers responses
    if (bytesReceived > 0) {
        // printf("server DH init response:\n");
        // for (int i = 0; i < bytesReceived; i++) {
        //     printf("%02x ", (unsigned char)serverResponse[i]); 
        // }
        // printf("\n");
    } else {
        printf("No server DH response recieved :(\n");
        // random error message code
        exit(1);
    }

    ServerDHResponse *dhResponse = extractServerDHResponse(serverResponse);

    // store f globally
    fGlobal = malloc(dhResponse -> fLen + sizeof(uint32_t));
    mpintLenNetworkOrder = htonl(dhResponse -> fLen);
    memcpy(fGlobal, &mpintLenNetworkOrder, sizeof(uint32_t));
    memcpy(fGlobal + sizeof(uint32_t), dhResponse -> f, dhResponse -> fLen);
    fGlobalLen = dhResponse -> fLen + sizeof(uint32_t);

    // derive shared secret
    klen = DH_size(dh);
    kbuf = malloc(klen);
    f = BN_new();
    BN_bin2bn(dhResponse -> f, dhResponse -> fLen, f);
    printf("F:\n");
    BN_print_fp(stdout, f);
    printf("\n");

    DH_compute_key(kbuf, f, dh);
    
    printf("Klen: %zu\n", klen);
    printf("K: \n");
    for (int i = 0; i < klen; i++) {
        printf("%02x ", kbuf[i]);
    }
    printf("\n");

    // encode K as mpint
    RawByteArray *twosK = addTwosComplementBit(kbuf, klen);
    RawByteArray *mpintK = malloc(sizeof(RawByteArray));
    unsigned char *mpintKdata = malloc(twosK -> size + sizeof(uint32_t));
    mpintLenNetworkOrder = htonl(twosK -> size);
    memcpy(mpintKdata, &mpintLenNetworkOrder, sizeof(uint32_t));
    memcpy(mpintKdata + sizeof(uint32_t), twosK -> data, twosK -> size);
    mpintK -> data = mpintKdata;
    mpintK -> size = twosK -> size + sizeof(uint32_t);

    // save K globally for use in encryption later
    kGlobal = malloc(mpintK -> size);
    kGlobalLen = mpintK -> size;
    memcpy(kGlobal, mpintK -> data, kGlobalLen);

    RawByteArray *verificationMessage = concatenateVerificationMessage(dhResponse -> hostKeyType, dhResponse -> hostKeyTypeLen, dhResponse -> publicKey, dhResponse -> publicKeyLen, mpintK -> data, mpintK -> size);

    // verify server
    if (verifyServerSignature(dhResponse, verificationMessage)) {
        printf("Server's signature verified successfully!\n");
    } else {
        printf("Error: Server's signature verification failed\n");
        // come up with better exit code
        exit(1);
    }

    // cleanup - NOT CONFIDENT THAT WE ARE FREEING EVERYTHING CORRECTLY
    // BN_free(p);
    // BN_free(g);
    DH_free(dh);
    free(eBytes);
    free(e -> data);
    free(e);
    free(buffer);
    // free(payload -> data);
    free(payload);
    free(packet -> data);
    free(packet);
    free(serverResponse);
    cleanupServerDHResponse(dhResponse);
    free(kbuf);
    BN_free(f);
    free(twosK -> data);
    free(twosK);
    free(mpintK -> data);
    free(mpintK);
    free(verificationMessage -> data);
    free(verificationMessage);
    
    return 0;
}

RawByteArray *generateNewKeysPacket() {
    int code = SSH_MSG_NEWKEYS;
    unsigned char data = code;
    
    RawByteArray *payloadAndSize = malloc(sizeof(RawByteArray));
    payloadAndSize -> data = &data;
    payloadAndSize -> size = 1;

    RawByteArray *packet = constructPacket(payloadAndSize);

    free(payloadAndSize -> data);
    free(payloadAndSize);

    return packet;
}

// RawByteArray *encrypt_chacha20_poly1305() {


//     return 
// }

// remember to free both data and struct
// func takes in no arguments bc global variables store required info
RawByteArray *deriveChaChaKey() {
    int sum = kGlobalLen + hashGlobalLen + 1 + hashGlobalLen; // string to hash is K || H || "B" || session_id
    unsigned char *toHash = malloc(sum);
    
    int offset = 0;
    memcpy(toHash, kGlobal, kGlobalLen);
    offset += kGlobalLen;
    memcpy(toHash + offset, hashGlobal, hashGlobalLen);
    offset += hashGlobalLen;
    toHash[offset] = 'C';
    // memcpy(toHash + offset, 'C', sizeof(char));
    offset += sizeof(char);
    memcpy(toHash + offset, hashGlobal, hashGlobalLen);

    RawByteArray *toHashAndSize = malloc(sizeof(RawByteArray));
    toHashAndSize -> data = toHash;
    toHashAndSize -> size = sum;

    RawByteArray *hash = computeSHA256Hash(toHashAndSize);

    // printf("toHash: \n");
    // for (int i = 0; i < toHashAndSize -> size; i++) {
    //     printf("%02x", toHashAndSize -> data[i]);
    // }
    // printf("\n");

    free(toHash);
    free(toHashAndSize);

    return hash;
}

size_t writeAlgoList(unsigned char *buffer, const char *list) {
    uint32_t len = htonl(strlen(list));
    memcpy(buffer, &len, sizeof(len));       // Write the length prefix
    memcpy(buffer + sizeof(len), list, strlen(list));  // Write the name-list
    return sizeof(len) + strlen(list);
}

// remember to free both struct AND data
RawByteArray *constructKexPayload() {
    size_t offset = 0;
    // for now hard coding buffer size is fine bc we dont have many algos, but in the future
    // we should either be smarter with how we allocate, or use malloc() and realloc()
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer    

    buffer[0] = SSH_MSG_KEXINIT;
    offset += 1;

    RawByteArray *cookie = generateRandomBytes(16);
    memcpy(buffer + offset, cookie -> data, 16);
    offset += 16;
    free(cookie -> data);
    free(cookie);

    // replace this with config file of same format in the future
    const char *algorithms[] = {
        // kex_algorithms
        "diffie-hellman-group14-sha256",
        // server_host_key_algorithms
        "ssh-ed25519", 
        // encryption_algorithms_client_to_server 
        "chacha20-poly1305@openssh.com",
        // encryption_algorithms_server-to-client
        "chacha20-poly1305@openssh.com",
        // mac_algorithms_client_to_server
        "none",
        // mac_algorithms_server_to_client
        "none",
        // compression_algorithms_client_to_server
        "none",
        // compression_algorithms_server_to_client
        "none",
        // languages_client_to_server
        "",
        // languages_server_to_client
        "",
        // terminating character
        0
    };

    for (int k = 0; algorithms[k] != 0; k++) {
        offset += writeAlgoList(buffer + offset, algorithms[k]);
    }

    // Add boolean (first_kex_packet_follows)
    buffer[offset] = 0;
    offset += 1;

    uint32_t reserved = htonl(0);  // Reserved field, set to 0
    buffer[offset] = reserved;
    offset += 4;
    
    RawByteArray *payload = malloc(sizeof(RawByteArray));
    payload -> data = malloc(offset);
    memcpy(payload->data, buffer, offset); // need to do it this way, or memory leak ensues
    payload -> size = offset;
    
    return payload;
}

// should add error codes later
int sendProtocol(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer

    // send client protocol to server
    char *protocol = "SSH-2.0-mySSH\r\n";
    int sentBytes = send(sock, protocol, strlen(protocol), 0);

    // save client protocol globally for use in sendDiffieHellmanExchange()
    V_C = malloc(strlen(protocol) + sizeof(uint32_t) - (2 * sizeof(char))); // dont want to include carriage return or new line
    uint32_t networkProtocolLen = htonl(strlen(protocol) - 2); // -2 for /r & /n
    memcpy(V_C, &networkProtocolLen, sizeof(uint32_t));
    memcpy(V_C + sizeof(uint32_t), protocol, strlen(protocol) - (2 * sizeof(char)));
    // strcpy((char *)V_C, protocol);
    V_C_length = strlen(protocol) + sizeof(uint32_t) - (2 * sizeof(char));

    if (sentBytes != -1) {
        printf("Successful protocol send! Number of protocol bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    ssize_t bytesReceived = recv(sock, buffer, BUFFER_SIZE, 0);
    
    // save server protocol globally for use in sendDiffieHellmanExchange()
    V_S = malloc(bytesReceived + sizeof(uint32_t) - (2 * sizeof(char)));
    networkProtocolLen = htonl(bytesReceived - 2);
    memcpy(V_S, &networkProtocolLen, sizeof(uint32_t));
    memcpy(V_S + sizeof(uint32_t), buffer, bytesReceived - (2 * sizeof(char)));
    V_S_length = bytesReceived + sizeof(uint32_t) - (2 * sizeof(char));

    if (bytesReceived > 0) {
        printf("server protocol: %s", buffer);
    } else {
        printf("No server protocol received :(\n");
    }

    return 0;
}

// returns pointer to RawByteArray stuct that includes the generated random bytes in data variable
// remember to FREE the struct AND data when done with it
RawByteArray* generateRandomBytes(int numBytes) {
    // seeding random number generator using VERY specific clock time
    struct timespec ts;
    srandom(ts.tv_sec ^ ts.tv_nsec);

    // allocate space for the struct
    RawByteArray *bytes = malloc(sizeof(RawByteArray));
    assert(bytes != NULL);

    // allocate space for the data
    bytes->data = malloc(numBytes);
    assert(bytes->data != NULL);

    bytes->size = numBytes;

    for (int i = 0; i < numBytes; i++) {
        bytes->data[i] = random() % 256;
    }

    return bytes;
}

int sendKexInit (int sock) {
    RawByteArray *payload = constructKexPayload();
    RawByteArray *packet = constructPacket(payload);

    // save globally for use later in sendDiffieHellmanExchange()
    I_C = malloc(sizeof(uint32_t) + payload -> size);
    uint32_t networkInitLen = htonl(payload -> size);
    memcpy(I_C, &networkInitLen, sizeof(uint32_t));
    memcpy(I_C + sizeof(uint32_t), payload -> data, payload -> size);
    I_C_length = sizeof(uint32_t) + payload -> size;
    
    // printing for debugging:
    // printf("PACKET:\n");
    // for (int i = 0; i < packet -> size; i++) {
    //     printf("%02x ", packet->data[i]);
    // }
    // printf("\n");
        
    int sentBytes = send(sock, packet -> data, packet -> size, 0);

    free(payload->data);
    free(payload);
    free(packet->data);
    free(packet);
    
    if (sentBytes != -1) {
        printf("Successful kex send! Number of kex bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    unsigned char buffer[BUFFER_SIZE*2];
    memset(buffer, 0, BUFFER_SIZE*2);  // Clear the buffer
    
    // recv only returns the ssh payload it seems
    size_t bytesReceived = recv(sock, buffer, BUFFER_SIZE*2, 0);    
    if (bytesReceived > 0) {
        // printf("kex init response:\n");
        // for (int i = 0; i < bytesReceived; i++) {
        //     printf("%02x ", buffer[i]);
        // }
        // printf("\n");
    } else {
        printf("No server response received :(\n");
    }

    uint32_t hostPacketLen = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    uint32_t hostPadLen = buffer[4];
    printf("packet len: %u | host pad len: %u\n", hostPacketLen, hostPadLen);

    uint32_t size = hostPacketLen - hostPadLen - 1; // -1 for padding size byte
    I_S = malloc(sizeof(uint32_t) + size); 
    networkInitLen = htonl(size);
    memcpy(I_S, &networkInitLen, sizeof(uint32_t));
    memcpy(I_S + sizeof(uint32_t), buffer + 5, size);
    I_S_length = sizeof(uint32_t) + size;

    return 0;
}

int start_client(const char *host, const int port) {
    struct sockaddr_in address;
    int sock = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_port = htons(22); // THIS IS THE PORT THAT THE CLIENT CONNECTS TO
    // inet_pton(AF_INET, "127.0.0.1", &address.sin_addr); // this is the host address to connect to
    inet_pton(AF_INET, host, &address.sin_addr);

    int output = connect(sock, (struct sockaddr *)&address, sizeof(address));
    
    if (output == 0) {
        printf("successful connection\n");
    } else {
        printf("no connection\n");
    }

    sendProtocol(sock);

    sendKexInit(sock);

    sendDiffieHellmanExchange(sock);
    
    RawByteArray *encryptionKey = deriveChaChaKey();

    printf("ENCRYPTION KEY:\n");
    for (int i = 0; i < encryptionKey -> size; i++) {
        printf("%02x ", encryptionKey -> data[i]);
    }
    printf("\n");

    // encrypt_chacha20_poly1305();

    // RawByteArray *newKeysPacket = RawByteArraygenerateNewKeysPacket();

    close(sock);

    // cleanup
    free(encryptionKey -> data);
    free(encryptionKey);

    return 0;
}

int main(int argc, char **argv) {
    // check & get command line arguments
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    const char *host = argv[1];
    const int port = atoi(argv[2]);

    start_client(host, port);

    // free global variables
    free(V_C);
    free(V_S);
    free(I_C);
    free(I_S);
    free(fGlobal);
    free(eGlobal);
    free(hashGlobal);
    free(kGlobal);

    return 0;
}