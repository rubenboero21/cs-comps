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
#define BLOCKSIZE 16 // aes (our encryption algorithm) cipher size is 16, will need to make 
                     // this dynamic when we implement multiple possible algos

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

    size_t hostSigDataLen = hostSigLen - hostSigTypeLen - sizeof(uint32_t);
    serverResponse -> hostSigDataLen = hostSigDataLen;

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
RawByteArray* encodeMpint(const unsigned char* pub_key, int pub_key_len) {
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

// WE NEED TO COMPUTE K BEFORE WE CAN VERIFY THE HOST
/*

*/
int verifyServerSignature(ServerDHResponse *dhResponse, const unsigned char *message, size_t message_len) {
    EVP_PKEY *serverPublicKey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;

    // Load the server's public key from dhResponse
    const unsigned char *p = dhResponse->publicKey;
    serverPublicKey = d2i_PUBKEY(NULL, &p, dhResponse->publicKeyLen);
    if (serverPublicKey == NULL) {
        printf("Error: Could not load server's public key\n");
        goto cleanup;
    }

    // Create a digest context for verifying the signature
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error: Could not create digest context\n");
        goto cleanup;
    }

    // Initialize the verification operation
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, serverPublicKey) != 1) {
        printf("Error: Could not initialize digest verify operation\n");
        goto cleanup;
    }

    // Add the message that was signed (typically the client DH public key, server DH public key, and other data)
    if (EVP_DigestVerifyUpdate(mdctx, message, message_len) != 1) {
        printf("Error: Could not update digest with message\n");
        goto cleanup;
    }

    // Perform the verification using the server's signature
    if (EVP_DigestVerifyFinal(mdctx, dhResponse->hostSigData, dhResponse->hostSigDataLen) == 1) {
        printf("Server's signature verified successfully!\n");
        ret = 1;  // Signature is valid
    } else {
        printf("Error: Server's signature verification failed\n");
    }

    cleanup:
        if (mdctx) EVP_MD_CTX_free(mdctx);
        if (serverPublicKey) EVP_PKEY_free(serverPublicKey);
        
        return ret;
}

// is it weird to only pass in half the variables we need, should we make all the variables we 
// need global?
// NEED TO ADD K TO THE FUNC PARAMS & FUNC BODY WHEN WE HAVE IT WORKING
RawByteArray *concatenateVerificationMessage(unsigned char *K_S, size_t K_S_length, unsigned char *e, size_t eLen, unsigned char *f, size_t fLen) {
    // remember to add K's len
    int sum = V_C_length + V_S_length + I_C_length + I_S_length + K_S_length + eLen + fLen;
    unsigned char *message = malloc(sum);
    int offset = 0;
    memcpy(message, V_C, V_C_length);
    offset += V_C_length;
    memcpy(message + offset, V_S, V_S_length);
    offset += V_S_length;
    memcpy(message + offset, I_C, I_C_length);
    offset += I_C_length;
    memcpy(message + offset, I_S, I_S_length);
    offset += I_S_length;
    memcpy(message + offset, K_S, K_S_length);
    offset += K_S_length;
    memcpy(message + offset, e, eLen);
    offset += eLen;
    memcpy(message + offset, f, fLen);
    offset += fLen;
    // memcpy(message + offset, K, KLen);

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
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
    EVP_PKEY *params = NULL, *dhkey = NULL;
    BIO *out = NULL;
    BIGNUM *p = NULL, *g = NULL;
    OSSL_PARAM dhParams[3];
    unsigned char *pBin = NULL, *gBin = NULL;
    int pSize = 0, gSize = 0;

    // create group 14 parameters with bignum
    p = BN_new();
    BN_get_rfc3526_prime_2048(p);
    g = BN_new();
    BN_set_word(g, 2);

    pSize = BN_num_bytes(p);
    gSize = BN_num_bytes(g);

    // allocate memory for pBin and gBin
    pBin = (unsigned char*)OPENSSL_malloc(pSize);
    gBin = (unsigned char*)OPENSSL_malloc(gSize);

    // convert p and g into binary form 
    // need to pad out binary to ensure standard size
    BN_bn2binpad(p, pBin, pSize);
    BN_bn2binpad(g, gBin, gSize);

    // initialize the parameter context for DH key generation 
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

    // prepare the DH parameters (p and g) using OSSL_PARAM array 
    dhParams[0] = OSSL_PARAM_construct_BN("p", pBin, pSize);
    dhParams[1] = OSSL_PARAM_construct_BN("g", gBin, gSize);
    dhParams[2] = OSSL_PARAM_construct_end();

    // use EVP_PKEY_fromdata to create an EVP_PKEY using the DH parameters 
    EVP_PKEY_fromdata_init(pctx);
    EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_KEY_PARAMETERS, dhParams);

    // generate a new DH key
    kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &dhkey);

    // extract the public key BIGNUM
    BIGNUM *eBN = NULL;
    EVP_PKEY_get_bn_param(dhkey, "pub", &eBN);

    int eLen = BN_num_bytes(eBN);  // get the length of the public key in bytes
    unsigned char *eNetworkOrder = (unsigned char *)malloc(eLen);

    BN_bn2bin(eBN, eNetworkOrder);

    BN_free(eBN);

    // swap endian-ness from little-endian to big-endian
    for (int i = 0; i < eLen / 2; i++) {
        unsigned char temp = eNetworkOrder[i];
        eNetworkOrder[i] = eNetworkOrder[eLen - i - 1];
        eNetworkOrder[eLen - i - 1] = temp;
    }
    
    RawByteArray *e = encodeMpint(eNetworkOrder, eLen);

    printf("public key (e)\n");
    printf("len of key: %zu\n", e -> size);
    for (int i = 0; i < e -> size; i++) {
        printf("%02x ", e -> data[i]);
    }
    printf("\n");

    unsigned char *buffer = malloc(e -> size + 1 + 4);
    buffer[0] = SSH_MSG_KEXDH_INIT;
    uint32_t mpintLenNetworkOrder = htonl(e->size);
    memcpy(buffer + 1, &mpintLenNetworkOrder, sizeof(uint32_t));
    memcpy(buffer + 5, e -> data, e -> size);
    free(e -> data);

    /* Optional: Print the private key */
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out && dhkey) {
        EVP_PKEY_print_private(out, dhkey, 0, NULL);
    }

    RawByteArray *payload = malloc(sizeof(RawByteArray));
    assert(payload != NULL);

    payload -> data = buffer;
    payload -> size = e -> size + 1 + 4; // +1 for message code, +4 for mpint len
    free(e);

    RawByteArray *packet = constructPacket(payload);
    free(payload);

    int sentBytes = send(sock, packet -> data, packet -> size, 0);
    free(buffer);
    // still need to free packet data even though we malloced data
    free(packet -> data);
    free(packet);

    if (sentBytes != -1) {
        printf("Successful DH init send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    unsigned char serverResponse[BUFFER_SIZE];
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
    }

    ServerDHResponse *dhResponse = extractServerDHResponse(serverResponse);

    // importing f into a PKEY:

    BIGNUM *fBN = BN_new();
    BN_bin2bn(dhResponse -> f, dhResponse -> fLen, fBN);

    EVP_PKEY_CTX *peerCtx = NULL;
    EVP_PKEY *peerkey = NULL;
    OSSL_PARAM peerParams[4];  // add space for the peer's public key (f)
    peerCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

    // prepare the parameters for peer's public key
    peerParams[0] = OSSL_PARAM_construct_BN("p", pBin, pSize);  
    peerParams[1] = OSSL_PARAM_construct_BN("g", gBin, gSize); 
    peerParams[2] = OSSL_PARAM_construct_BN("pub", dhResponse -> f, dhResponse -> fLen); 
    peerParams[3] = OSSL_PARAM_construct_end(); 

    EVP_PKEY_fromdata_init(peerCtx);
    EVP_PKEY_fromdata(peerCtx, &peerkey, EVP_PKEY_PUBLIC_KEY, peerParams);
    
    printf("FFFFF:\n");
    for (int i = 0; i < dhResponse -> fLen; i++) {
        printf("%02x ", dhResponse -> f[i]);
    }
    printf("\n");

    // PRINTINg TO DEBUG
    EVP_PKEY_print_public(out, peerkey, 0, NULL);

    // UTILITY FUNC COMMENTED OUT TO MAKE OUTPUT NICER
    // printServerDHResponse(serverResponse);

    /* Cleanup */
    cleanupServerDHResponse(dhResponse);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(dhkey);
    BIO_free(out);
    BN_free(p);
    BN_free(g);
    OPENSSL_free(pBin);
    OPENSSL_free(gBin);
    free(eNetworkOrder);
    // cleaning up importing f into a pkey struct
    EVP_PKEY_CTX_free(peerCtx);
    BN_free(f_bn);
    EVP_PKEY_free(peerkey);
    
    return 0;
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
        "aes256-gcm@openssh.com",
        // encryption_algorithms_server-to-client
        "aes256-gcm@openssh.com",
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
    assert(payload != NULL);
    payload -> data = malloc(offset);
    assert(payload -> data != NULL);
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
    V_C = malloc(strlen(protocol));
    strcpy((char *)V_C, protocol);
    V_C_length = strlen(protocol);

    if (sentBytes != -1) {
        printf("Successful protocol send! Number of protocol bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    ssize_t bytesReceived = recv(sock, buffer, BUFFER_SIZE, 0);
    
    // save server protocol globally for use in sendDiffieHellmanExchange()
    V_S = malloc(bytesReceived);
    memcpy(V_S, buffer, bytesReceived);
    V_S_length = bytesReceived;

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
    I_C = malloc(packet -> size);
    memcpy(I_C, packet -> data, packet -> size);
    I_C_length = packet -> size;
    
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
    size_t bytes_received = recv(sock, buffer, BUFFER_SIZE*2, 0);    
    if (bytes_received > 0) {
        // printf("kex init response:\n");
        // for (int i = 0; i < bytes_received; i++) {
        //     printf("%02x ", buffer[i]);
        // }
        // printf("\n");
    } else {
        printf("No server response received :(\n");
    }
    I_S = malloc(bytes_received);
    memcpy(I_S, buffer, bytes_received);
    I_S_length = bytes_received;

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

    close(sock);

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

    // print statements to verify that we set the global variables correctly
    // printf("V_C: %s", V_C);
    // printf("V_S: ");
    // for (int i = 0; i < V_S_length; i++) {
    //     printf("%c", V_S[i]);
    // }
    // printf("I_C: ");
    // for (int i = 0; i < I_C_length; i++) {
    //     printf("%02x ", I_C[i]);
    // }
    // printf("\n");
    // printf("I_S: ");
    // for (int i = 0; i < I_S_length; i++) {
    //     printf("%02x ", I_S[i]);
    // }
    // printf("\n");

    // free global variables
    free(V_C);
    free(V_S);
    free(I_C);
    free(I_S);

    return 0;
}