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

// reconfigure function to return fully formed buffer instead of struct
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
    BN_CTX *ctx = BN_CTX_new();

    // The hexadecimal string of the large prime number
    const char *dec_p = "179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709443744987040614133027225199282902678806752087668575421517593598750987686174230035765418575759253034351398231325725407913926913700368287011373398768091883503046227554347558084606727487827952418640696792688525182940744594346680383290646398559634075870581264286138294341137223850641288670503013560026865243610027162515030030355267727759725909829152094493524065674458344998942458734692009285522536863347001533675641010656474986735217703362542264146700204831485697210250651166782115923297011106429116212904724187171122008088043202229093524581401255666120033670080402790080202191684272654515254399699370040567264383018087008547654978276482248091426934533697229180942196329793820487681125920873366627499406527030202177760181942146413108341442773885458407891653564404469024077168140547753382825103823336302164105055070477215157";
    
    const char *dec_q = "223007451985298231915202312437100749111329175504351105431327990454642337831366880058906686265279511210098194571530602282577501199797707785201201221928889180928140658535013118089743522164835056446560835971773153520488484844838504327932232082649699123188949972407960472313788617963894201826095563681298913913920405867149242493709613033320640919825176353380967282893052962740660530353400226190856108062418611865422231252510582470786781705383895556066415893049838855561200418626943765622033402192235159065960915204135572305599154330983325664700128300081813298078425025927588306115996399270187196828286406704600";
    
    const char *dec_g = "2";
    // Convert the decimal string to a BIGNUM
    BN_dec2bn(&p, dec_p);
    BN_dec2bn(&q, dec_q);
    BN_dec2bn(&g, dec_g);

    // Generate a random private key x
    // x should be a random number less than p
    do {
        BN_rand_range(x, q);
    } while (BN_is_zero(x)); // Ensure x is not zero

    // Compute e = g^x mod p
    BN_mod_exp(e, g, x, p, ctx);

    // Convert e to MPINT
    int mpintLen = BN_num_bytes(e) + 1; // +1 len for sign byte
    unsigned char *mpint = NULL;

    // Allocate memory for MPINT (length + 1 for sign byte)
    mpint = malloc(mpintLen);
    assert(mpint != NULL);

    // Get the binary representation of e
    BN_bn2bin(e, mpint + 1);
    
    // Set the sign byte
    if (BN_is_negative(e)) {
        mpint[0] = 0xFF; // Negative
    } else {
        mpint[0] = 0x00; // Positive
    }

    // allocate memory for the entire payload
    // +1 for message code, +4 for len of mpint
    unsigned char *buffer = malloc(mpintLen + 1 + 4);
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
    payload -> size = mpintLen + 1;

    printf("len of mpint: %02x\n", mpintLen);
    printf("constructed payload:\n");
    for (int i = 0; i < payload -> size; i++) {
        printf("%02x ", payload->data[i]);
    }
    printf("\n");
    // WIRESHARK IS SHOWING THAT THE PADDING IS GETTING INCLUDED IN THE VALUE OF E

    RawByteArray *packet = constructPacket(payload);
    free(payload);

    send(sock, packet -> data, packet -> size, 0);
    free(buffer);
    // don't need to free packet -> data bc we set it to buffer, didn't malloc anything new
    free(packet);

    // Print the MPINT
    // printf("MPINT (length: %d): ", length_in_bytes + 1);
    // for (int i = 0; i < length_in_bytes + 1; i++) {
    //     printf("%02X ", mpint[i]);
    // }
    // printf("\n");

    // // Print the BIGNUM in decimal to verify it was stored correctly
    // char *p_str = BN_bn2dec(p);
    // printf("Stored p: %s\n", p_str);

    // // Print the BIGNUM in decimal to verify it was stored correctly
    // char *q_str = BN_bn2dec(q);
    // printf("Stored q: %s\n", q_str);

    // // Print results
    // printf("Private key x: ");
    // BN_print_fp(stdout, x);
    // printf("\n");
    
    // printf("Computed e (g^x mod p): ");
    // BN_print_fp(stdout, e);
    // printf("\n");

    // printf("Length of e: %d bytes\n", length_in_bytes);

    // Free the memory
    BN_free(p);
    BN_free(q);
    BN_free(g);
    BN_free(x);
    BN_free(e);
    BN_CTX_free(ctx);
    
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
        "ssh-ed25519-cert-v01@openssh.com", 
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
        printf("response: %s\n", buffer);
    } else {
        printf("No server response recieved :(\n");
    }

    // printing out some of the response (buffer is too small for all of it)
    // for (int i = 0; i < sizeof(buffer); i++) {
    //     printf("%02x ", buffer[i]);
    // }
    // printf("\n");

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