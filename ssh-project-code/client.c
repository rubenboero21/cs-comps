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

/* Takes in a pointer to a BIGNUM and converts it to unsigned char* in mpint form
   FREES the e that is passed in*/
RawByteArray *bignumToMpint(BIGNUM *e) {
    RawByteArray *mpintAndSize = malloc(sizeof(RawByteArray));
    assert(mpintAndSize != NULL);

    // convert e to mpint
    int eLen = BN_num_bytes(e);
    size_t mpintLen = eLen; // initial mpint length (might need adjustment)
    unsigned char *eBin = malloc(eLen); // temporary buffer for BN binary
    assert(eBin != NULL);

    BN_bn2bin(e, eBin);

    // check if the most significant bit of the first byte is set for positive numbers
    int prependZero = 0;
    if (!BN_is_negative(e) && (eBin[0] & 0x80)) {
        prependZero = 1; // need to prepend 0x00 for positive number with MSB set
        mpintLen += 1; // increase mpint length by 1 byte
    }
    mpintAndSize -> size = mpintLen;

    unsigned char *mpint = malloc(mpintLen);
    assert(mpint != NULL);

    // set the sign or prepend byte
    if (BN_is_negative(e)) {
        mpint[0] = 0xFF; // negative number, no need for extra zero
    } else if (prependZero) {
        mpint[0] = 0x00; // positive number with MSB set, prepend 0x00
    }
    BN_free(e);

    // copy the binary representation of e to the MPINT buffer
    if (prependZero) {
        memcpy(mpint + 1, eBin, eLen); // copy with the prepended zero byte
    } else {
        memcpy(mpint, eBin, eLen); // no prepend needed
    }
    free(eBin);

    mpintAndSize -> data = mpint;

    return mpintAndSize;
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
    unsigned char *hostKeyTypePtr = hostKeyType; // need to keep a pointer to free later
    hostKeyType = memcpy(hostKeyType, payload + offset, hostKeyTypeLen);
    offset += hostKeyTypeLen;
    hostKeyType[hostKeyTypeLen] = '\0';
    printf("host key type: %s\n", hostKeyType);
    free(hostKeyTypePtr);

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

    // idk what this number means since its larger than the host sig data section in wireshark
    uint32_t hostSigLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("host signature length: %u bytes\n", hostSigLen);

    uint32_t hostSigTypeLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    printf("host signature length: %u bytes\n", hostSigTypeLen);

    // add print of host key signature type after i fix seg fault error from printing above
    unsigned char *hostSigType = malloc(hostSigTypeLen + 1);
    unsigned char *hostSigTypePtr = hostSigType;
    hostSigType = memcpy(hostSigType, payload + offset, hostSigTypeLen);
    offset += hostSigTypeLen;
    hostSigType[hostSigTypeLen] = '\0';
    printf("host key signature type: %s\n", hostSigType);
    free(hostSigTypePtr);
    
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

// to get the libraries to work, need to run the following command (on Ruben's arm mac with
// openssl installed via homebrew)
// gcc client.c -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
// gcc <file name> -I<path to openssl install>/include -L<path to openssl install>/lib -lssl -lcrypto
int sendDiffieHellmanExchange(int sock) {
    // Initialize BIGNUM structures
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *e = BN_new();
    // idk what context does
    BN_CTX *ctx = BN_CTX_new();

    // group 14 p value is defined in RFC 3526
    const char *hex_p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    const char *dec_g = "2";

    BN_hex2bn(&p, hex_p);
    BN_dec2bn(&g, dec_g);

    // q = (p - 1)/2
    // NOT CONVINCED THIS q equation above is correct
    BIGNUM *pMinusOne = BN_new();
    BN_sub(pMinusOne, p, BN_value_one()); // p - 1
    BN_rshift1(q, pMinusOne); // divide by 2
    BN_free(pMinusOne);

    // generate x such that 1 < x < q
    do {
        BN_rand_range(x, q);
    } while (BN_cmp(x, BN_value_one()) == -1); // BN_cmp(a, b) returns -1 if a < b
    BN_free(q);

    // compute e = g^x mod p
    BN_mod_exp(e, g, x, p, ctx);

    BN_free(p);
    BN_free(g);
    BN_free(x);
    BN_CTX_free(ctx);

    RawByteArray *mpint = bignumToMpint(e);

    // printf("E!: \n");
    // for (int i = 0; i < mpint -> size; i++) {
    //     printf("%02x ", (unsigned char)mpint -> data[i]); 
    // }
    // printf("\n");

    // allocate memory for the entire payload
    // +1 for message code, +4 for len of mpint
    unsigned char *buffer = malloc(1 + 4 + mpint -> size);
    assert(buffer != NULL);

    buffer[0] = SSH_MSG_KEXDH_INIT;
    // need to add the len of the mpint to buffer
    buffer[1] = (unsigned char)((mpint -> size >> 24) & 0xFF); // most significant byte
    buffer[2] = (unsigned char)((mpint -> size >> 16) & 0xFF);
    buffer[3] = (unsigned char)((mpint -> size >> 8) & 0xFF);
    buffer[4] = (unsigned char)(mpint -> size & 0xFF); 

    memcpy(buffer + 5, mpint -> data, mpint -> size);

    RawByteArray *payload = malloc(sizeof(RawByteArray));
    assert(payload != NULL);

    payload -> data = buffer;
    payload -> size = mpint -> size + 1 + 4; // +1 for message code, +4 for mpint len
    free(mpint -> data);
    free(mpint);

    RawByteArray *packet = constructPacket(payload);
    free(payload);

    int sentBytes = send(sock, packet -> data, packet -> size, 0);
    free(buffer);
    // don't need to free packet -> data bc we set it to buffer, didn't malloc anything new
    free(packet);

    if (sentBytes != -1) {
        printf("Successful DH init send! Number of bytes sent: %i\n", sentBytes);
    } else {
        printf("Send did not complete successfully.\n");
    }
    
    // print part of DH server response
    unsigned char serverResponse[BUFFER_SIZE];
    memset(serverResponse, 0, BUFFER_SIZE);  // Clear the buffer    
    ssize_t bytesReceived = recv(sock, serverResponse, BUFFER_SIZE, 0);
    // REMEMBER WE NEED TO RECV AGAIN BC SERVER SENDS 2 MESSAGES BACK TO BACK

    if (bytesReceived > 0) {
        // this next line prints something, i dont know what its printing
        // printf("server DH init response: %s\n", serverResponse);
        printf("server DH init response:\n");
        for (int i = 0; i < bytesReceived; i++) {
            printf("%02x ", (unsigned char)serverResponse[i]); 
        }
        printf("\n");
    } else {
        printf("No server DH response received :(\n");
    }

    // UTILITY FUNC COMMENTED OUT TO MAKE OUTPUT NICER
    // printServerDHResponse(serverResponse);

    // ssize_t bytesReceived = 0;
    // char serverResponse[BUFFER_SIZE];
    // while ((bytesReceived = recv(sock, serverResponse, BUFFER_SIZE, 0)) > 0) {
    //     // Process the received chunk of data
    //     // Accumulate it, if necessary, to get the complete message
    //     printf("Received chunk:\n");
    //     for (int i = 0; i < bytesReceived; i++) {
    //         // printf("%02x ", serverResponse[i]);
    //         printf("%02x ", serverResponse[i]);
    //     }
    //     printf("\n");
    //     // You may want to break the loop when you've got the full message
    // }
    
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