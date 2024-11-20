#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>
#include "client.h"

// openssl libraries (for DH)
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// openssl libraries (for encryption/auth)
#include <openssl/hmac.h>

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_NEWKEYS 21
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_REQUEST 98
#define BLOCKSIZE 16 
#define SHA1_DIGEST_LENGTH 20
#define MAC_SIZE 20

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
    
    size_t payloadLength = payload->size;
    
    // + 5 bytes: 4 for packet length, 1 for padding length
    unsigned char paddingLength = BLOCKSIZE - ((payloadLength + 5) % BLOCKSIZE);

    // ensure minimum 4 bytes of padding
    if (paddingLength < 4) {
        paddingLength += BLOCKSIZE;
    }

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

    // copy contents into our packet (binaryPacket)
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

// Adds the leading 2s complement byte if necessary to ensure that e is positive
// remember to free returned rawbytearray data, and then rawbytearray itself
RawByteArray* addTwosComplementBit(const unsigned char* pubKey, int pubKeyLen) {
    int needsPadding = (pubKey[0] & 0x80) != 0;
    int mpintLen = pubKeyLen + (needsPadding ? 1 : 0);
    
    unsigned char* mpint = malloc(mpintLen);
    if (needsPadding) {
        mpint[0] = 0x00;
        memcpy(mpint + 1, pubKey, pubKeyLen);
    } else {
        memcpy(mpint, pubKey, pubKeyLen);
    }
    
    RawByteArray* mpintAndSize = malloc(sizeof(RawByteArray));
    mpintAndSize -> data = mpint;
    mpintAndSize -> size = mpintLen;

    return mpintAndSize;
}

// Function to compute the SHA-256 hash of a message and return it as a pointer to RawByteArray
RawByteArray *computeSHA256Hash(const RawByteArray *message) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 
    const EVP_MD *md = EVP_sha256(); 
    RawByteArray *outputHash = malloc(sizeof(RawByteArray));
    unsigned int hashLength = 0;

    if (mdctx == NULL || outputHash == NULL) {
        printf("Error: Could not create digest context or allocate memory for output hash\n");
        if (mdctx) EVP_MD_CTX_free(mdctx); 
        if (outputHash) free(outputHash); 
        return NULL;
    }

    // initialize the digest context for SHA-256
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Error: Could not initialize digest\n");
        EVP_MD_CTX_free(mdctx);
        free(outputHash);
        return NULL;
    }

    // add the input message to be hashed
    if (EVP_DigestUpdate(mdctx, message->data, message->size) != 1) {
        printf("Error: Could not update digest\n");
        EVP_MD_CTX_free(mdctx);
        free(outputHash);
        return NULL;
    }

    // allocate memory for the hash output
    outputHash->data = (unsigned char *)malloc(EVP_MD_size(md));
    if (outputHash->data == NULL) {
        printf("Error: Could not allocate memory for output hash data\n");
        EVP_MD_CTX_free(mdctx);
        free(outputHash);
        return NULL;
    }

    // finalize the digest and store the result in outputHash->data
    if (EVP_DigestFinal_ex(mdctx, outputHash->data, &hashLength) != 1) {
        printf("Error: Could not finalize digest\n");
        free(outputHash->data);  
        free(outputHash);
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    outputHash->size = hashLength;

    // clean up
    EVP_MD_CTX_free(mdctx);

    return outputHash; 
}

int verifyServerSignature(ServerDHResponse *dhResponse, RawByteArray *message) {
    EVP_PKEY *serverPublicKey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    // load the server's EDDSA public key from raw byte array 
    serverPublicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, dhResponse->publicKey, dhResponse->publicKeyLen);
    if (serverPublicKey == NULL) {
        printf("Error: Could not load server's public key\n");
        goto cleanup;
    }

    // check for Ed25519 key type
    int keyType = EVP_PKEY_base_id(serverPublicKey);
    if (keyType != EVP_PKEY_ED25519) {
        printf("Error: serverPublicKey is not of type Ed25519\n");
        goto cleanup;
    }

    // create a digest context for verifying the signature
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error: Could not create digest context\n");
        goto cleanup;
    }

    // initialize the verification operation for Ed25519
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, serverPublicKey) != 1) {
        printf("Error: Could not initialize digest verify operation\n");
        goto cleanup;
    }

    RawByteArray *hashedMessage = computeSHA256Hash(message);
    // printf("HASHED MESSAGE:\n");
    // for (int i = 0; i < hashedMessage -> size; i++) {
    //     printf("%02x ", hashedMessage -> data[i]);
    // }
    // printf("\n");

    // save our hash as a global variable for use in encryption key derivation
    hashGlobal = malloc(hashedMessage -> size);
    hashGlobalLen = hashedMessage -> size;
    memcpy(hashGlobal, hashedMessage -> data, hashGlobalLen);
    

    // perform the verification using the server's signature (ed25519 doesn't use DigestUpdate)
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

    // printf("V_C: \n");
    // for (int i = offset; i < V_C_length + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");
    
    offset += V_C_length;
    memcpy(message + offset, V_S, V_S_length);

    // printf("V_S: \n");
    // for (int i = offset; i < V_S_length + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");
    
    offset += V_S_length;
    memcpy(message + offset, I_C, I_C_length);
    
    // printf("I_C: \n");
    // for (int i = offset; i < I_C_length + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");
    
    offset += I_C_length;
    memcpy(message + offset, I_S, I_S_length);
    
    // printf("I_S: \n");
    // for (int i = offset; i < I_S_length + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");

    offset += I_S_length;

    // int temp = offset;
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

    // printf("K_S: \n");
    // for (int i = temp; i < offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");

    memcpy(message + offset, eGlobal, eGlobalLen);

    // printf("E: \n");
    // for (int i = offset; i < eGlobalLen + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");

    offset += eGlobalLen;
    memcpy(message + offset, fGlobal, fGlobalLen);

    // printf("F: \n");
    // for (int i = offset; i < fGlobalLen + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");

    offset += fGlobalLen;
    memcpy(message + offset, K, K_length);

    // printf("K: \n");
    // for (int i = offset; i < K_length + offset; i++) {
    //     printf("%02x ", message[i]);
    // }
    // printf("\n");

    RawByteArray *messageAndSize = malloc(sizeof(RawByteArray));
    messageAndSize -> data = message;
    messageAndSize -> size = sum;

    return messageAndSize;
}

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
    // printf("Prime (p): ");
    // BN_print_fp(stdout, p);
    // printf("\n");

    // Print g
    // printf("Generator (g): ");
    // BN_print_fp(stdout, g);
    // printf("\n");

    DH_generate_key(dh);

    // DH_get0_pqg(dh, &p, &g, NULL);
    DH_get0_key(dh, &pub_key, &priv_key);

    // Print private key
    // printf("Private Key (x): ");
    // BN_print_fp(stdout, priv_key);
    // printf("\n");

    int eSize = BN_num_bytes(pub_key);
    // printf("size of e: %i bytes\n", eSize);
    
    // Print private key
    // printf("Public Key (e): ");
    // BN_print_fp(stdout, pub_key);
    // printf("\n");
    
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
        printf("No server DH response received :(\n");
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
    // printf("F:\n");
    // BN_print_fp(stdout, f);
    // printf("\n");

    DH_compute_key(kbuf, f, dh);
    
    // printf("Klen: %zu\n", klen);
    // printf("K: \n");
    // for (int i = 0; i < klen; i++) {
    //     printf("%02x ", kbuf[i]);
    // }
    // printf("\n");

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
    assert(payloadAndSize != NULL);

    payloadAndSize -> data = malloc(sizeof(data));
    assert(payloadAndSize -> data != NULL);

    payloadAndSize->data[0] = code;
    payloadAndSize -> size = sizeof(data);

    // constructPacket frees payloadAndSize and its data
    RawByteArray *packet = constructPacket(payloadAndSize);

    free(payloadAndSize -> data);
    free(payloadAndSize);

    return packet;
}

// remember to free both data and struct
// func only takes in letter bc global variables store other required info
RawByteArray *deriveKey(char letter) {
    int sum = kGlobalLen + hashGlobalLen + 1 + hashGlobalLen; // string to hash is K || H || "B" || session_id
    unsigned char *toHash = malloc(sum);
    
    int offset = 0;
    memcpy(toHash, kGlobal, kGlobalLen);
    offset += kGlobalLen;
    memcpy(toHash + offset, hashGlobal, hashGlobalLen);
    offset += hashGlobalLen;
    toHash[offset] = letter;
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

// hard coded to encrypt using aes128-ctr
// pass in 1 for encrypt, 0 for decrypt
// remember to free struct and data
RawByteArray *aes128EncryptDecrypt(EVP_CIPHER_CTX *ctx, RawByteArray *message, int encrypt) {
    int len = 0;
    RawByteArray *result = malloc(sizeof(RawByteArray));
    assert(result != NULL);

    // initialize result with length and data set to NULL (in case of an error)
    result -> data = NULL;
    result -> size = 0;

    // allocate memory for the ciphertext/plaintext (they are the same length for aes128ctr)
    result -> data = malloc(message -> size);
    assert(result -> data != NULL);

    // choose the correct operation based on the 'encrypt' flag (1 for encryption, 0 for decryption)
    if (encrypt) {
        EVP_EncryptUpdate(ctx, result->data, &len, message->data, message->size);

    } else {
        EVP_DecryptUpdate(ctx, result->data, &len, message->data, message->size);
    }

    result -> size = len;

    return result;
}

// remember to free data and struct
RawByteArray *computeHmacSha1(RawByteArray *integrityKey, RawByteArray *packet, uint32_t sequenceNumber) {
    unsigned int macSize;
    unsigned char data[4 + packet -> size];
    size_t data_size = 4 + packet->size;

    RawByteArray *mac = malloc(sizeof(RawByteArray));
    mac -> data = malloc(SHA1_DIGEST_LENGTH);
    mac -> size = SHA1_DIGEST_LENGTH;

    // copy the sequence number (4 bytes) and packet data into data buffer
    sequenceNumber = htonl(sequenceNumber);
    memcpy(data, &sequenceNumber, 4);
    memcpy(data + 4, packet -> data, packet -> size);

    // printf("SEQ || unencrypted message:\n");
    // for (int i = 0; i < data_size; i++) {
    //     printf("%02x ", data[i]);
    // }
    // printf("\n");
    // printf("size of data: %zu\n", data_size);

    // compute HMAC-SHA1
    HMAC(EVP_sha1(), integrityKey -> data, integrityKey -> size, data, data_size, mac -> data, &macSize);
    
    // delete macSize when not using this print out, its the only place its used
    // printf("mac size (should be 20): %i\n", macSize);

    return mac;
}

size_t writeAlgoList(unsigned char *buffer, const char *list) {
    uint32_t len = htonl(strlen(list));
    memcpy(buffer, &len, sizeof(len)); 
    memcpy(buffer + sizeof(len), list, strlen(list)); 
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
        "aes128-ctr",
        // encryption_algorithms_server-to-client
        "aes128-ctr",
        // mac_algorithms_client_to_server
        "hmac-sha1",
        // mac_algorithms_server_to_client
        "hmac-sha1",
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

    // add boolean (first_kex_packet_follows)
    buffer[offset] = 0;
    offset += 1;

    // reserved field, set to 0
    uint32_t reserved = htonl(0);  
    buffer[offset] = reserved;
    offset += 4;
    
    RawByteArray *payload = malloc(sizeof(RawByteArray));
    payload -> data = malloc(offset);
    memcpy(payload->data, buffer, offset);
    payload -> size = offset;
    
    return payload;
}

// should add error codes later
int sendProtocol(int sock) {
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // clear the buffer

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
        printf("Server protocol: %s", buffer);
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
    memset(buffer, 0, BUFFER_SIZE*2);  // clear the buffer
    
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
    // printf("packet len: %u | host pad len: %u\n", hostPacketLen, hostPadLen);

    uint32_t size = hostPacketLen - hostPadLen - 1; // -1 for padding size byte
    I_S = malloc(sizeof(uint32_t) + size); 
    networkInitLen = htonl(size);
    memcpy(I_S, &networkInitLen, sizeof(uint32_t));
    memcpy(I_S + sizeof(uint32_t), buffer + 5, size);
    I_S_length = sizeof(uint32_t) + size;

    return 0;
}

RawByteArray *concatenateMacToMsg(RawByteArray *mac, RawByteArray *ciphertext) {
    int bufferSize = mac -> size + ciphertext -> size;
    
    RawByteArray *buffer = malloc(sizeof(RawByteArray));
    buffer -> data = malloc(bufferSize);
    buffer -> size = bufferSize;

    memcpy(buffer -> data, ciphertext -> data, ciphertext -> size);
    memcpy(buffer -> data + ciphertext -> size, mac -> data, mac -> size);

    return buffer;
}

// userauth argument is a boolean, 1 means to send userauth req, 0 means to send connection req
int sendServiceReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum) {
    RawByteArray *serviceReq = malloc(sizeof(RawByteArray));
    assert(serviceReq != NULL);

    unsigned char serviceName[12] = "ssh-userauth";

    int offset = 0;
    unsigned char data[1 + sizeof(uint32_t) + sizeof(serviceName)]; // + 1 for 1 byte message code    
    data[0] = SSH_MSG_SERVICE_REQUEST;
    offset += 1;

    uint32_t size = htonl(sizeof(serviceName));
    memcpy(data + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(data + offset, serviceName, sizeof(serviceName));
    
    serviceReq -> data = data;
    serviceReq -> size = 1 + sizeof(uint32_t) + sizeof(serviceName);

    // printf("Unencrypted Service Request:\n");
    // for (int i = 0; i < serviceReq -> size; i++) {
    //     printf("%02x ", serviceReq -> data[i]);
    // }
    // printf("\n");

    RawByteArray *serviceReqPacket = constructPacket(serviceReq);
    // printf("service req packet:\n");
    // for (int i = 0; i < serviceReqPacket -> size; i++) {
    //     printf("%02x ", serviceReqPacket -> data[i]);
    // }
    // printf("\n");

    RawByteArray *ciphertext = aes128EncryptDecrypt(encryptCtx, serviceReqPacket, 1);

    RawByteArray *mac = computeHmacSha1(integrityKey, serviceReqPacket, seqNum);
    
    RawByteArray *encMsgBuffer = concatenateMacToMsg(mac, ciphertext);

    // printf("encMsgBuffer:\n");
    // for (int i = 0; i < encMsgBuffer -> size; i++) {
    //     printf("%02x ", encMsgBuffer -> data[i]);
    // }
    // printf("\n");

    int sentBytes = send(sock, encMsgBuffer -> data, encMsgBuffer -> size, 0);

    if (sentBytes != -1) {
        printf("Successful encrypted service request packet send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }

    // cleanup
    free(serviceReq);
    free(serviceReqPacket -> data);
    free(serviceReqPacket);
    free(ciphertext -> data);
    free(ciphertext);
    free(mac -> data);
    free(mac);
    free(encMsgBuffer -> data);
    free(encMsgBuffer);

    return 0;   
}

int sendUserAuthReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum) {
    RawByteArray *userAuthReq = malloc(sizeof(RawByteArray));
    assert(userAuthReq != NULL);

    // left in so we can uncomment while testing (no need to put in credentials every run of code)
    // unsigned char username[4] = "kali";
    // unsigned char password[4] = "kali";
    
    char username[20];
    char password[20];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);

    // printf("username: %s, password: %s\n", username, password);

    unsigned char serviceName[14] = "ssh-connection";
    unsigned char methodName[8] = "password";

    // first +1 is for message code byte, 2nd +1 is for false boolean
    // subtract 1 from strlen bc last character is newline, which we don't want
    userAuthReq -> size = 1 + (sizeof(uint32_t) + strlen(username) - 1) + (sizeof(uint32_t) + sizeof(serviceName)) + (sizeof(uint32_t) + sizeof(methodName)) + 1 + (sizeof(uint32_t) + strlen(password) - 1);    
    userAuthReq -> data = malloc(userAuthReq -> size);

    // construct userAuthBuffer
    unsigned char userAuthBuffer[userAuthReq -> size];
    int offset = 0;
    uint32_t size = 0;
    userAuthBuffer[offset] = SSH_MSG_USERAUTH_REQUEST;
    offset += 1;
    size = htonl(strlen(username) - 1);
    memcpy(userAuthBuffer + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(userAuthBuffer + offset, username, sizeof(username));
    offset += strlen(username) - 1;
    size = htonl(sizeof(serviceName));
    memcpy(userAuthBuffer + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(userAuthBuffer + offset, serviceName, sizeof(serviceName));
    offset += sizeof(serviceName);
    size = htonl(sizeof(methodName));
    memcpy(userAuthBuffer + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t); 
    memcpy(userAuthBuffer + offset, methodName, sizeof(methodName));
    offset += sizeof(methodName);
    userAuthBuffer[offset] = 0;
    offset += 1;
    size = htonl(strlen(password) - 1);
    memcpy(userAuthBuffer + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t); 
    memcpy(userAuthBuffer + offset, password, strlen(password) - 1);

    memcpy(userAuthReq -> data, userAuthBuffer, userAuthReq -> size);

    RawByteArray *userAuthReqPacket = constructPacket(userAuthReq);

    // printf("unencrypted send auth:\n");
    // for (int i = 0; i < userAuthReq -> size; i++) {
    //     printf("%02x ", userAuthReq -> data[i]);
    // }
    // printf("\n");

    // printf("unencrypted send auth packet:\n");
    // for (int i = 0; i < userAuthReqPacket -> size; i++) {
    //     printf("%02x ", userAuthReqPacket -> data[i]);
    // }
    // printf("\n");

    RawByteArray *ciphertext = aes128EncryptDecrypt(encryptCtx, userAuthReqPacket, 1);

    // printf("ciphertext send auth:\n");
    // for (int i = 0; i < ciphertext -> size; i++) {
    //     printf("%02x ", ciphertext -> data[i]);
    // }
    // printf("\n");

    RawByteArray *mac = computeHmacSha1(integrityKey, userAuthReqPacket, seqNum);

    // printf("MAC: \n");
    // for (int i = 0; i < mac -> size; i++) {
    //     printf("%02x ", mac -> data[i]);
    // }
    // printf("\n");

    // cat MAC to end of ciphertext and send to server
    RawByteArray *encMsgBuffer = concatenateMacToMsg(mac, ciphertext);

    // printf("message to send:\n");
    // for (int i = 0; i < encMsgBuffer -> size; i++) {
    //     printf("%02x ", encMsgBuffer -> data[i]);
    // }
    // printf("\n");

    int sentBytes = send(sock, encMsgBuffer -> data, encMsgBuffer -> size, 0);

    if (sentBytes != -1) {
        printf("Successful encrypted user auth packet send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }

    // cleanup
    free(userAuthReq -> data);
    free(userAuthReq);
    free(userAuthReqPacket -> data);
    free(userAuthReqPacket);
    free(ciphertext -> data);
    free(ciphertext);
    free(mac -> data);
    free(mac);
    free(encMsgBuffer -> data);
    free(encMsgBuffer);

    return 0;
}

// returns 1 if MAC is verified, 0 if MAC is not verified
int recvMsgVerifyMac(int sock, int bufferSize, RawByteArray *integrityKey, int seqNum, EVP_CIPHER_CTX *decryptCtx) {
    // prob want to use realloc later for dynamic size
    unsigned char serverResponse[bufferSize];
    memset(serverResponse, 0, bufferSize);  // clear the buffer    

    ssize_t bytesReceived = recv(sock, serverResponse, bufferSize, 0);

    if (bytesReceived > 0) {
        printf("Encrypted Server Response (length=%zd):\n", bytesReceived);
        // for (int i = 0; i < bytesReceived; i++) {
        //     printf("%02x ", (unsigned char)serverResponse[i]); 
        // }
        // printf("\n");
    } else {
        printf("No server user response received :(\n");
        // random error message code
        exit(1);
    }

    // get server message minus MAC bytes
    unsigned char data[bytesReceived - MAC_SIZE];
    size_t size = bytesReceived - MAC_SIZE;
    RawByteArray serverResponseAndSize = {data, size};
    memcpy(serverResponseAndSize.data, serverResponse, serverResponseAndSize.size);
    
    unsigned char mac[MAC_SIZE];
    memcpy(mac, serverResponse + serverResponseAndSize.size, MAC_SIZE);
    // printf("SERVER MAC:\n");
    // for (int i = 0; i < MAC_SIZE; i++) {
    //     printf("%02x ", mac[i]);
    // }
    // printf("\n");

    RawByteArray *decResponse = aes128EncryptDecrypt(decryptCtx, &serverResponseAndSize, 0);
    
    // printf("DEC SERVER RESPONSE:\n");
    // for (int i = 0; i < decResponse -> size; i++) {
    //     printf("%02x ", decResponse -> data[i]);
    // }
    // printf("\n");

    // printf("INTEGRITY KEY\n");
    // for (int i = 0; i < integrityKey -> size; i++) {
    //     printf("%02x ", integrityKey -> data[i]);
    // }
    // printf("\n");

    RawByteArray *computedMac = computeHmacSha1(integrityKey, decResponse, seqNum);

    int ret = 0;
    // ensure that their mac matches what we expect when we compute it 
    if (strncmp((const char *)computedMac -> data, (const char *)mac, MAC_SIZE) != 0) {
        printf("Server MAC invalid\n");
        ret = 0;
    } else {
        printf("Server MAC valid\n");
        ret = 1;
    }

    // cleanup
    free(decResponse -> data);
    free(decResponse);
    free(computedMac -> data);
    free(computedMac);
    
    return ret;
}

/*
byte      SSH_MSG_CHANNEL_REQUEST (98)
uint32    recipient channel
string    "exec"
boolean   want reply
string    command
*/
int sendChannelReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum) {
       
    const char exec[4] = "exec";
    
    // const char command[6] = "whoami";
    char command[30];
    
    printf("Enter command: ");
    fgets(command, 30, stdin);

    // we hard coded channel to be 0 in sendChannelOpenReq()
    uint32_t recipChannel = htonl(0);
    uint32_t execLen = htonl(sizeof(exec));
    uint32_t commandLen = htonl(strlen(command) - 1);
    
    size_t size = 1 + sizeof(uint32_t) + (sizeof(uint32_t) + sizeof(exec)) + 1 + (sizeof(uint32_t) + strlen(command) - 1);
    
    int offset = 0;
    unsigned char data[size];
    
    data[0] = SSH_MSG_CHANNEL_REQUEST;
    offset += 1;
    
    memcpy(data + offset, &recipChannel, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(data + offset, &execLen, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(data + offset, exec, sizeof(exec));
    offset += sizeof(exec);

    // want reply = true (1)
    data[offset] = 1;
    offset += 1;

    memcpy(data + offset, &commandLen, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    memcpy(data + offset, command, strlen(command) - 1);

    // printf("CHANNEL REQ EXEC:\n");
    // for (int i = 0; i < sizeof(data); i++) {
    //     printf("%02x ", data[i]);
    // }
    // printf("\n");

    RawByteArray channelReq = {data, size};

    RawByteArray *channelReqPacket = constructPacket(&channelReq);

    RawByteArray *ciphertext = aes128EncryptDecrypt(encryptCtx, channelReqPacket, 1);

    RawByteArray *mac = computeHmacSha1(integrityKey, channelReqPacket, seqNum);
    
    RawByteArray *encMsgBuffer = concatenateMacToMsg(mac, ciphertext);

    int sentBytes = send(sock, encMsgBuffer -> data, encMsgBuffer -> size, 0);

    if (sentBytes != -1) {
        printf("Successful channel open packet send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }

    // cleanup
    free(channelReqPacket -> data);
    free(channelReqPacket);
    free(ciphertext -> data);
    free(ciphertext);
    free(mac -> data);
    free(mac);
    free(encMsgBuffer -> data);
    free(encMsgBuffer);

    return 0;
}

int sendChannelOpenReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum) {
    RawByteArray *channelOpen = malloc(sizeof(RawByteArray));
    assert(channelOpen != NULL);

    unsigned char channelType[7] = "session";

    int offset = 0;
    // + 1 for 1 byte message code, uint32_t x 4 for channel type str length, sender 
    // channel ID, window size, packet size    
    unsigned char data[1 + sizeof(uint32_t)*4 + sizeof(channelType)]; 
    data[0] = SSH_MSG_CHANNEL_OPEN;
    offset += 1;

    uint32_t size = htonl(sizeof(channelType));
    memcpy(data + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(data + offset, channelType, sizeof(channelType));
    offset += sizeof(channelType);

    // sender channel - unique ID for channel chosen by client
    uint32_t senderChannel = 0;
    size = htonl(senderChannel);
    memcpy(data + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // hard coding window size and max packet size
    uint32_t initWindowSize = BUFFER_SIZE;
    size = htonl(initWindowSize);
    memcpy(data + offset, &size, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    uint32_t maxPacketSize = BUFFER_SIZE;
    size = htonl(maxPacketSize);
    memcpy(data + offset, &size, sizeof(uint32_t));

    channelOpen -> data = data;
    channelOpen -> size = sizeof(data);

    RawByteArray *channelOpenPacket = constructPacket(channelOpen);

    RawByteArray *ciphertext = aes128EncryptDecrypt(encryptCtx, channelOpenPacket, 1);

    RawByteArray *mac = computeHmacSha1(integrityKey, channelOpenPacket, seqNum);
    
    RawByteArray *encMsgBuffer = concatenateMacToMsg(mac, ciphertext);

    int sentBytes = send(sock, encMsgBuffer -> data, encMsgBuffer -> size, 0);

    if (sentBytes != -1) {
        printf("Successful channel open packet send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }

    // cleanup
    free(channelOpen);
    free(channelOpenPacket -> data);
    free(channelOpenPacket);
    free(ciphertext -> data);
    free(ciphertext);
    free(mac -> data);
    free(mac);
    free(encMsgBuffer -> data);
    free(encMsgBuffer);

    return 0;   
}

// function to read the 2 messages that are part of 1 packet
int recvWinAdjChanSuccVerifyMac(int sock, int bufferSize, RawByteArray *integrityKey, int seqNum, EVP_CIPHER_CTX *decryptCtx) {
    unsigned char serverResponse[bufferSize];
    memset(serverResponse, 0, bufferSize); 

    ssize_t bytesReceived = recv(sock, serverResponse, bufferSize, 0);

    if (bytesReceived > 0) {
        // printf("Encrypted Window Adjust and Channel Success Message (length=%zd):\n", bytesReceived);
        // for (int i = 0; i < bytesReceived; i++) {
        //     printf("%02x ", (unsigned char)serverResponse[i]); 
        // }
        // printf("\n");
    } else {
        printf("No server response received :(\n");
        // random error message code
        exit(1);
    }

    unsigned char winAdj[32]; // hard coded for now
    unsigned char winAdjMac[MAC_SIZE];

    memcpy(winAdj, serverResponse, sizeof(winAdj));
    memcpy(winAdjMac, serverResponse + sizeof(winAdj), MAC_SIZE);

    RawByteArray winAdjAndSize = {winAdj, sizeof(winAdj)};

    RawByteArray *winAdjDec = aes128EncryptDecrypt(decryptCtx, &winAdjAndSize, 0);
    
    // printf("DEC WIN-ADJ SERVER RESPONSE:\n");
    // for (int i = 0; i < winAdjDec -> size; i++) {
    //     printf("%02x ", winAdjDec -> data[i]);
    // }
    // printf("\n");

    RawByteArray *computedWinAdjMac = computeHmacSha1(integrityKey, winAdjDec, seqNum);
    
    int winAdjRet = 0;
    // ensure that their mac matches what we expect when we compute it 
    if (strncmp((const char *)computedWinAdjMac -> data, (const char *)winAdjMac, MAC_SIZE) != 0) {
        printf("WinAdj Server MAC invalid\n");
        winAdjRet = 0;
    } else {
        printf("WinAdj Server MAC valid\n");
        winAdjRet = 1;
    }

    unsigned char chanSucc[16];
    unsigned char chanSuccMac[MAC_SIZE];

    memcpy(chanSucc, serverResponse + sizeof(winAdj) + MAC_SIZE, sizeof(chanSucc));
    memcpy(chanSuccMac, serverResponse + sizeof(winAdj) + MAC_SIZE + sizeof(chanSucc), MAC_SIZE);

    RawByteArray chanSuccAndSize = {chanSucc, sizeof(chanSucc)};

    RawByteArray *chanSuccDec = aes128EncryptDecrypt(decryptCtx, &chanSuccAndSize, 0);
    
    // printf("DEC CHAN-SUCCESS SERVER RESPONSE:\n");
    // for (int i = 0; i < chanSuccDec -> size; i++) {
    //     printf("%02x ", chanSuccDec -> data[i]);
    // }
    // printf("\n");

    // SEQ NUM NEEDS TO BE 1 HIGHER
    RawByteArray *computedChanSuccMac = computeHmacSha1(integrityKey, chanSuccDec, seqNum + 1);

    // printf("computed chan succ mac:\n");
    // for (int i = 0; i < computedChanSuccMac -> size; i++) {
    //     printf("%02x ", computedChanSuccMac -> data[i]);
    // }
    // printf("\nreceived chan succ mac:\n");
    // for (int i = 0; i < sizeof(chanSuccMac); i++) {
    //     printf("%02x ", chanSuccMac[i]);
    // }
    // printf("\n");
    
    int chanSuccRet = 0;
    // ensure that their mac matches what we expect when we compute it 
    if (strncmp((const char *)computedChanSuccMac -> data, (const char *)chanSuccMac, MAC_SIZE) != 0) {
        printf("ChanSucc Server MAC invalid\n");
        chanSuccRet = 0;
    } else {
        printf("ChanSucc Server MAC valid\n");
        chanSuccRet = 1;
    }
    
    // cleanup
    free(winAdjDec -> data);
    free(winAdjDec);
    free(computedWinAdjMac -> data);
    free(computedWinAdjMac);

    free(chanSuccDec -> data);
    free(chanSuccDec);
    free(computedChanSuccMac -> data);
    free(computedChanSuccMac);

    return winAdjRet && chanSuccRet;
}

// there may be other messages that are sent in this packet, may need to 
// modify the function name and body to accomodate
int recvChanDataVerifyMac(int sock, int bufferSize, RawByteArray *integrityKey, int seqNum, EVP_CIPHER_CTX *decryptCtx) {
    unsigned char serverResponse[bufferSize];
    memset(serverResponse, 0, bufferSize); 

    ssize_t bytesReceived = recv(sock, serverResponse, bufferSize, 0);

    if (bytesReceived > 0) {
        // printf("Encrypted Channel Data Message (length=%zd):\n", bytesReceived);
        // for (int i = 0; i < bytesReceived; i++) {
        //     printf("%02x ", (unsigned char)serverResponse[i]); 
        // }
        // printf("\n");
    } else {
        printf("No server response received :(\n");
        // random error message code
        exit(1);
    }

    RawByteArray packetAndSize = {serverResponse, sizeof(serverResponse)};

    RawByteArray *fullPacketDec = aes128EncryptDecrypt(decryptCtx, &packetAndSize, 0);

    // read the length of the 1st message
    int offset = 0;
    uint32_t messageLen = (fullPacketDec -> data[offset] << 24) | (fullPacketDec -> data[offset + 1] << 16) | (fullPacketDec -> data[offset + 2] << 8) | fullPacketDec -> data[offset + 3];
    offset += sizeof(uint32_t);
    // printf("message len: %d\n", messageLen);
    // we can check if there are multiple message in 1 packet by comparing the number
    // of bytes read to the message len
    fullPacketDec -> size = messageLen + sizeof(uint32_t);

    // read the length of the data string
    offset += 1; // skip padding len byte
    
    // unsigned char messageCode = fullPacketDec -> data[offset];
    offset += 1;
    // printf("message code: %i\n", messageCode);

    // skip the recipient channel number
    offset += sizeof(uint32_t);

    uint32_t dataLen = (fullPacketDec -> data[offset] << 24) | (fullPacketDec -> data[offset + 1] << 16) | (fullPacketDec -> data[offset + 2] << 8) | fullPacketDec -> data[offset + 3];
    offset += sizeof(uint32_t);
    // printf("data len: %d\n", dataLen);
    
    // read the contents of the string and the MAC
    unsigned char chanData[dataLen];
    unsigned char chanDataMac[MAC_SIZE];

    memcpy(chanData, fullPacketDec -> data + offset, sizeof(chanData));
    memcpy(chanDataMac, serverResponse + (messageLen + sizeof(uint32_t)), MAC_SIZE);

    RawByteArray chanDataAndSize = {chanData, sizeof(chanData)};
    
    printf("Server response:\n");
    for (int i = 0; i < chanDataAndSize.size; i++) {
        printf("%c", chanDataAndSize.data[i]);
    }
    printf("\n");

    RawByteArray *computedChanDataMac = computeHmacSha1(integrityKey, fullPacketDec, seqNum);
    
    int chanDataRet = 0;
    // ensure that their mac matches what we expect when we compute it 
    if (strncmp((const char *)computedChanDataMac -> data, (const char *)chanDataMac, MAC_SIZE) != 0) {
        printf("Channel Data Server MAC invalid\n");
        chanDataRet = 0;
    } else {
        printf("Channel Data Server MAC valid\n");
        chanDataRet = 1;
    }

    // cleanup
    free(computedChanDataMac -> data);
    free(computedChanDataMac);
    free(fullPacketDec -> data);
    free(fullPacketDec);

    return chanDataRet;
}

// control function for encryption and MAC messages (post DH messages)
int sendReceiveEncryptedData(int sock, uint32_t *seqNum) {
    RawByteArray *encKeyCtoS = deriveKey('C');
    encKeyCtoS -> size = 16;
    RawByteArray *encKeyStoC = deriveKey('D');
    encKeyStoC -> size = 16;

    // printf("C to S ENCRYPTION KEY:\n");
    // for (int i = 0; i < encKeyCtoS -> size; i++) {
    //     printf("%02x", encKeyCtoS -> data[i]);
    // }
    // printf("\n");

    // printf("S to C ENCRYPTION KEY:\n");
    // for (int i = 0; i < encKeyStoC -> size; i++) {
    //     printf("%02x", encKeyStoC -> data[i]);
    // }
    // printf("\n");

    RawByteArray *ivCtoS = deriveKey('A');
    ivCtoS -> size = 16;
    RawByteArray *ivStoC = deriveKey('B');
    ivStoC -> size = 16;

    // printf("C to S IV:\n");
    // for (int i = 0; i < ivCtoS -> size; i++) {
    //     printf("%02x", ivCtoS -> data[i]);
    // }
    // printf("\n");

    // printf("S to C IV:\n");
    // for (int i = 0; i < ivStoC -> size; i++) {
    //     printf("%02x", ivStoC -> data[i]);
    // }
    // printf("\n");
    
    // derive key uses sha256, so output is 32 bytes, our mac algo only wants 20 byte key,
    // so truncate the output by setting size to 20
    RawByteArray *integrityKeyCtoS = deriveKey('E');
    integrityKeyCtoS -> size = 20;
    RawByteArray *integrityKeyStoC = deriveKey('F');
    integrityKeyStoC -> size = 20;
    // we aren't computing the server to client integrity key because we don't plan
    // on having out client check the server's MAC (for now)

    // printf("INTEGRITY KEY:\n");
    // for (int i = 0; i < integrityKey -> size; i++) {
    //     printf("%02x", integrityKey -> data[i]);
    // }
    // printf("\n");

    // initialize the contexts we will use for encryption and decryption
    EVP_CIPHER_CTX *encryptCtx;
    encryptCtx = EVP_CIPHER_CTX_new();


    EVP_CIPHER_CTX *decryptCtx;
    decryptCtx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(encryptCtx, EVP_aes_128_ctr(), NULL, encKeyCtoS -> data, ivCtoS -> data);
    EVP_DecryptInit_ex(decryptCtx, EVP_aes_128_ctr(), NULL, encKeyStoC -> data, ivStoC -> data);
    
    sendServiceReq(sock, encryptCtx, integrityKeyCtoS, *seqNum);
    if (!recvMsgVerifyMac(sock, BUFFER_SIZE, integrityKeyStoC, *seqNum, decryptCtx)) {
        printf("ERROR: Invalid MAC\n");
        exit(1);
    }
    *seqNum += 1;

    sendUserAuthReq(sock, encryptCtx, integrityKeyCtoS, *seqNum);
    if (!recvMsgVerifyMac(sock, BUFFER_SIZE, integrityKeyStoC, *seqNum, decryptCtx)) {
        printf("ERROR: Invalid MAC\n");
        exit(1);
    }
    *seqNum += 1;

    sendChannelOpenReq(sock, encryptCtx, integrityKeyCtoS, *seqNum);
    // eating the global server response
    if (!recvMsgVerifyMac(sock, BUFFER_SIZE, integrityKeyStoC, *seqNum, decryptCtx)) {
        printf("ERROR: Invalid MAC\n");
        exit(1);
    }

    // read server's SSH_MSG_CHANNEL_OPEN_CONFIRMATION message
    // server sends 2 messages back to back, so need to add 1 to seqNum
    if (!recvMsgVerifyMac(sock, BUFFER_SIZE, integrityKeyStoC, *seqNum + 1, decryptCtx)) {
        printf("ERROR: Invalid MAC\n");
        exit(1);
    }
    *seqNum += 1;

    // send "whoami" command to the server
    sendChannelReq(sock, encryptCtx, integrityKeyCtoS, *seqNum);
    // recv window adj and channel sucess
    if (!recvWinAdjChanSuccVerifyMac(sock, BUFFER_SIZE, integrityKeyStoC, *seqNum + 1, decryptCtx)) {
        printf("ERROR: Either Invalid WinAdj or ChannSucc MAC\n");
        exit(1);
    }
    *seqNum += 1;

    // read channel data
    if (!recvChanDataVerifyMac(sock, BUFFER_SIZE, integrityKeyStoC, *seqNum + 2, decryptCtx)) {
        printf("ERROR: Invalid MAC\n");
        // exit(1);
    }
    *seqNum += 1;

    // cleanup
    free(encKeyCtoS -> data);
    free(encKeyCtoS);
    free(encKeyStoC -> data);
    free(encKeyStoC);
    free(ivCtoS -> data);
    free(ivCtoS);
    free(ivStoC -> data);
    free(ivStoC);
    free(integrityKeyCtoS -> data);
    free(integrityKeyCtoS);
    free(integrityKeyStoC -> data);
    free(integrityKeyStoC);
    EVP_CIPHER_CTX_free(encryptCtx);
    EVP_CIPHER_CTX_free(decryptCtx);

    return 0;
}

int sendNewKeysPacket(int sock) {
    RawByteArray *newKeysPacket = generateNewKeysPacket();
    // printf("NEW KEYS PACKET:\n");
    // for (int i = 0; i < newKeysPacket -> size; i++) {
    //     printf("%02x", newKeysPacket -> data[i]);
    // }
    // printf("\n");

    int sentBytes = send(sock, newKeysPacket -> data, newKeysPacket -> size, 0);
    
    if (sentBytes != -1) {
        printf("Successful newkeys packet send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }

    free(newKeysPacket -> data);
    free(newKeysPacket);

    return 0;
}

int startClient(const char *host, const int port) {
    struct sockaddr_in address;
    int sock = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, host, &address.sin_addr);

    int output = connect(sock, (struct sockaddr *)&address, sizeof(address));
    
    if (output == 0) {
        printf("Successful connection\n");
    } else {
        printf("No connection\n");
    }

    uint32_t seqNum = 0;

    sendProtocol(sock);
    // seqNum doesn't seem to be incremented after protocol packet

    sendKexInit(sock);
    seqNum += 1;

    sendDiffieHellmanExchange(sock);
    seqNum += 1;

    sendNewKeysPacket(sock);
    seqNum += 1;

    sendReceiveEncryptedData(sock, &seqNum);
    // seqNum is incremented implicitly in sendReceiveEncryptedData

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

    startClient(host, port);

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