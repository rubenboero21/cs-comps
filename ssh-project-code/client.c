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
#define BLOCKSIZE 16 // aes (our encryption algorithm) cipher size is 16, will need to make 
                     // this dynamic when we implement multiple possible algos

// remember to free the struct AND data
RawByteArray *constructPacket(RawByteArray *payload) {
    
    // Calculate padding length, calculate packet length, generate random padding, calculate TOTAL packet size
    size_t payloadLength = payload->size;
    
    unsigned char paddingLength = BLOCKSIZE - ((payloadLength + 5) % BLOCKSIZE);

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

    // Generate x such that 1 < x < q
    BIGNUM *one =  BN_new();
    BN_one(one); // setting one to hold 1
    do {
        BN_rand_range(x, q);
    } while (BN_cmp(x, one) == -1); // BN_cmp(a, b) returns -1 if a < b
    BN_free(one);
    BN_free(q);

    // Compute e = g^x mod p
    BN_mod_exp(e, g, x, p, ctx);

    BN_free(p);
    BN_free(g);
    BN_free(x);
    BN_CTX_free(ctx);

    // Convert e to MPINT
    int bnLen = BN_num_bytes(e);
    int mpintLen = bnLen; // Initial MPINT length (might need adjustment)
    unsigned char *mpint = NULL;
    unsigned char *bnBin = malloc(bnLen); // Temporary buffer for BN binary
    assert(bnBin != NULL);

    // Get the binary representation of e
    BN_bn2bin(e, bnBin);

    // Check if the MSB of the first byte is set for positive numbers
    int prependZero = 0;
    if (!BN_is_negative(e) && (bnBin[0] & 0x80)) {
        prependZero = 1; // Need to prepend 0x00 for positive number with MSB set
        mpintLen += 1; // Increase MPINT length by 1 byte
    }

    mpint = malloc(mpintLen);
    assert(mpint != NULL);

    // Set the sign or prepend byte
    if (BN_is_negative(e)) {
        mpint[0] = 0xFF; // Negative number, no need for extra zero
    } else if (prependZero) {
        mpint[0] = 0x00; // Positive number with MSB set, prepend 0x00
    }
    BN_free(e);

    // Copy the binary representation of e to the MPINT buffer
    if (prependZero) {
        memcpy(mpint + 1, bnBin, bnLen); // Copy with the prepended zero byte
    } else {
        memcpy(mpint, bnBin, bnLen); // No prepend needed
    }
    free(bnBin);

    // allocate memory for the entire payload
    // +1 for message code, +4 for len of mpint
    unsigned char *buffer = malloc(1 + 4 + mpintLen);
    assert(buffer != NULL);

    buffer[0] = SSH_MSG_KEXDH_INIT;
    // need to add the len of the mpint to buffer
    buffer[1] = (unsigned char)((mpintLen >> 24) & 0xFF); // most significant byte
    buffer[2] = (unsigned char)((mpintLen >> 16) & 0xFF);
    buffer[3] = (unsigned char)((mpintLen >> 8) & 0xFF);
    buffer[4] = (unsigned char)(mpintLen & 0xFF); 
    memcpy(buffer + 5, mpint, mpintLen);
    free(mpint);

    RawByteArray *payload = malloc(sizeof(RawByteArray));
    assert(payload != NULL);

    payload -> data = buffer;
    payload -> size = mpintLen + 1 + 4; // +1 for message code, +4 for mpint len

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
    char serverResponse[BUFFER_SIZE];
    ssize_t bytesRecieved = recv(sock, serverResponse, BUFFER_SIZE, 0);
    
    if (bytesRecieved > 0) {
        // this next line prints something, i dont know what its printing
        // printf("server DH init response: %s\n", serverResponse);
        // printf("server DH init response:\n");
        // for (int i = 0; i < sizeof(serverResponse); i++) {
        //     printf("%02x ", serverResponse[i]); 
        // }
        // printf("\n");
    } else {
        printf("No server DH response recieved :(\n");
    }
    
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
    
    ssize_t bytesRecieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytesRecieved > 0) {
        printf("server protocol: %s", buffer);
    } else {
        printf("No server protocol recieved :(\n");
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
    ssize_t bytes_recieved = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytes_recieved > 0) {
        // printf("kex init response:\n");
        // // printing out some of the response (buffer is too small for all of it)
        // for (int i = 0; i < sizeof(buffer); i++) {
        //     printf("%02x ", buffer[i]);
        // }
        // printf("\n");
    } else {
        printf("No server response recieved :(\n");
    }

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