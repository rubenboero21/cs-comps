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

// IDK WHAT SIZE BUFFER MAKES SENSE, LAWSUS USES 1024 A LOT, SO USING THAT FOR NOW
#define BUFFER_SIZE 1024
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_NEWKEYS 21
#define BLOCKSIZE 16 // aes (our encryption algorithm) cipher size is 16, will need to make 
                     // this dynamic when we implement multiple possible algos

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
    unsigned char *p_bin = NULL, *g_bin = NULL;
    OSSL_PARAM dh_params[3];
    int p_size = 0, g_size = 0;

    // Group 14 parameters
    const char* group14_p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    const int group14_g = 2;

    // Convert Group 14 prime to BIGNUM
    p = BN_new();
    BN_hex2bn(&p, group14_p_hex);

    // Create BIGNUM for generator
    g = BN_new();
    BN_set_word(g, group14_g);

    // Get sizes for p and g
    p_size = BN_num_bytes(p);
    g_size = BN_num_bytes(g);

    // Allocate memory for p_bin and g_bin
    p_bin = (unsigned char*)OPENSSL_malloc(p_size);
    g_bin = (unsigned char*)OPENSSL_malloc(g_size);

    // Convert p and g into binary form 
    // need to pad out binary to ensure standard size
    BN_bn2binpad(p, p_bin, p_size);
    BN_bn2binpad(g, g_bin, g_size);

    // Initialize the parameter context for DH key generation 
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

    // Prepare the DH parameters (p and g) using OSSL_PARAM array 
    dh_params[0] = OSSL_PARAM_construct_BN("p", p_bin, p_size);
    dh_params[1] = OSSL_PARAM_construct_BN("g", g_bin, g_size);
    dh_params[2] = OSSL_PARAM_construct_end();

    // Use EVP_PKEY_fromdata to create an EVP_PKEY using the DH parameters 
    EVP_PKEY_fromdata_init(pctx);

    EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_KEY_PARAMETERS, dh_params);

    // Create key generation context
    kctx = EVP_PKEY_CTX_new(params, NULL);

    // Generate a new DH key
    EVP_PKEY_keygen_init(kctx);

    EVP_PKEY_keygen(kctx, &dhkey);

    // Extract the public key e = g^x mod p
    // Extract the public key using EVP_PKEY_get1_encoded_public_key()

    // Create a buffer for the encoded public key
    unsigned char *pub_key_encoded = NULL;
    // size_t pub_key_len = 0;
    EVP_PKEY_get1_encoded_public_key(dhkey, &pub_key_encoded);

    // RawByteArray *mpint = bignumToMpint(pub_key_encoded);
    
    int pubLen = EVP_PKEY_bits(dhkey)/8;
    RawByteArray *mpint = encodeMpint(pub_key_encoded, pubLen);

    printf("public key (e)\n");
    printf("len of key: %zu\n", mpint -> size);
    for (int i = 0; i < mpint -> size; i++) {
        printf("%02x ", mpint -> data[i]);
    }
    printf("\n");

    unsigned char *buffer = malloc(mpint -> size + 1 + 4);
    buffer[0] = SSH_MSG_KEXDH_INIT;
    uint32_t mpint_len_network_order = htonl(mpint->size);
    memcpy(buffer + 1, &mpint_len_network_order, sizeof(uint32_t));
    memcpy(buffer + 5, mpint -> data, mpint -> size);
    free(mpint -> data);

    /* Optional: Print the private key */
    // out = BIO_new_fp(stdout, BIO_NOCLOSE);
    // if (out && dhkey) {
    //     EVP_PKEY_print_private(out, dhkey, 0, NULL);
    // }

    RawByteArray *payload = malloc(sizeof(RawByteArray));
    assert(payload != NULL);

    payload -> data = buffer;
    payload -> size = mpint -> size + 1 + 4; // +1 for message code, +4 for mpint len
    free(mpint);

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

    /* Cleanup */
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(dhkey);
    BIO_free(out);
    BN_free(p);
    BN_free(g);
    OPENSSL_free(p_bin);
    OPENSSL_free(g_bin);
    OPENSSL_free(pub_key_encoded);
    
    // UTILITY FUNC COMMENTED OUT TO MAKE OUTPUT NICER
    // printServerDHResponse(serverResponse);
    
    ServerDHResponse *dhResponse = extractServerDHResponse(serverResponse);
    // do stuff with response here
    cleanupServerDHResponse(dhResponse);

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

    if (sentBytes != -1) {
        printf("Successful protocol send! Number of protocol bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    ssize_t bytesReceived = recv(sock, buffer, BUFFER_SIZE, 0);
    
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
    
    unsigned char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);  // Clear the buffer
    
    // recv only returns the ssh payload it seems

    // the server response is larger than buffer size, so we need to recv() multiple times 
    // in order to fully clear the buffer of kex server messages
    ssize_t bytes_received = BUFFER_SIZE; // just so that it will enter the do while loop
    do {
        bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);    
        if (bytes_received > 0) {
            // printf("kex init response:\n");
            // for (int i = 0; i < bytes_received; i++) {
            //     printf("%02x ", buffer[i]);
            // }
            // printf("\n");
        } else {
            printf("No server response received :(\n");
        }
    } while (bytes_received == BUFFER_SIZE);

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
    return 0;
}