#include <openssl/evp.h>

// a struct to hold data and its size
typedef struct {
    unsigned char *data;
    size_t size;
} RawByteArray;

// a struct to hold the data that the server sends back in step 2 of DH exchange
typedef struct {
    uint32_t hostKeyTypeLen;
    unsigned char *hostKeyType;
    uint32_t publicKeyLen;
    unsigned char *publicKey;
    
    uint32_t fLen;
    unsigned char *f;

    uint32_t hostSigLen;
    uint32_t hostSigTypeLen;
    unsigned char *hostSigType;
    size_t hostSigDataLen;
    unsigned char *hostSigData; 
} ServerDHResponse;

/*
Input: Pointer to a RawByteArray struct that contains the payload data and size
Output: A struct containing the raw bytes of the packet in Binary Packet Protocol format, and 
        the size of the packet
*/
RawByteArray *constructPacket(RawByteArray *payload);

/*
Input: None (potentially a list of algorithms in the future)
Output: A RawByteArray struct containing the payload and the size
*/
RawByteArray *constructKexPayload();

/*
Input sock: The socket to send the protocol packet to
Output:
*/
int sendProtocol(int sock);

/*
Input: The number of random bytes to generate
Output: A pointer to a RawByteArray struct that contains the random bytes in the data variable
        and the size of the data in size variable
*/
RawByteArray* generateRandomBytes(int numBytes);

/*
Input: The socket to send the protocol packet to
Output: 
*/
int sendKexInit (int sock);

/*
Input: A host and port number to connect to 
Output: SOME ERROR CODES - NEED TO UPDATE
This function is a control function that calls the necessary steps of the SSH exchange
*/
int startClient(const char *host, const int port);

/*
Input: payload from which to extract the DH information
Extracts the server's public host key (K_S), the server's public DH key (f), 
and the signature of H (hash(V_C || V_S || I_C || I_S || K_S || e || f || K)) and stores 
them in a ServerDHResponse struct. The pointer to this struct is returned.
This is hard coded to work for our server response type
Remember to FREE the ServerDHResponse struct and its malloc'ed contents (data) when done
*/
ServerDHResponse *extractServerDHResponse(unsigned char* payload);

/* 
Input: ServerDHResponse struct
Frees all malloc'ed data from extractServerDHResponse function
*/
void cleanupServerDHResponse(ServerDHResponse *serverResponse);

/* 
Takes in server DH response payload, prints all sections of the payload 
(Wireshark-esque style)
*/
void printServerDHResponse(unsigned char* payload);

/*
Input pubKey: the public key to potentially add 2s complement byte to
Input pubKeyLen: the length of said public key
Returns: a pointer to a new RawByteArray struct with the updated public key and length
Adds the leading 2s complement byte if necessary to ensure that e is positive
Remember to free returned RawByteArray data, and then RawByteArray itself
*/
RawByteArray* addTwosComplementBit(const unsigned char* pubKey, int pubKeyLen);

/*
Input message: a RawByteArray struct containing the message to hash and its length
Returns a pointer to a RawByteArray containing the hash and its length
Remember to free returned RawByteArray data, and then RawByteArray itself
*/
RawByteArray *computeSHA256Hash(const RawByteArray *message);

/*
Input dhResponse: the server's DH response
Input message: the exchange message
Returns 1 if server is verified (from signature), 0 if server is not verified
*/
int verifyServerSignature(ServerDHResponse *dhResponse, RawByteArray *message);

/*
Input keyType: the type of key the server sends (string)
Input keyTypeLen: the length of keyType (4 bytes big endian order)
Input pubKey: the public key (f) of the server (mpint)
Input pubKeyLen: the length of pubKey (4 bytes big endian order)
Input K: the shared secret derived from the DH exchange (mpint)
Input K_length: the length of K (4 bytes big endian order)
Returns a pointer to a RawByteArray struct contaning the concatenation of the above input
and its length
Note, this function relies on global variables
*/
RawByteArray *concatenateVerificationMessage(unsigned char *keyType, size_t keyTypeLen, unsigned char *pubKey, size_t pubKeyLen, unsigned char *K, size_t K_length);

/*
Input sock: socket to send the DH responses to
Return SOME ERROR CODE
*/
int sendDiffieHellmanExchange(int sock);

/*
Returns a RawByteArray struct containing the ssh new keys packet and the size of the packet
Remember to free both the RawByteArray and RawByteArray data
*/
RawByteArray *generateNewKeysPacket();

/*
Input letter: the character in HASH(K || H || character || session_id)
Returns a pointer to a RawByteArray containing the key and its length
Note, this function relies on global variables
Remember to free both the RawByteArray and RawByteArray data
*/
RawByteArray *deriveKey(char letter);

/*
Input buffer: buffer to write theh algorithm list to
Input list: comma separated list of algorithms to write
Returns the size of the list
*/
size_t writeAlgoList(unsigned char *buffer, const char *list);

/*
Returns a pointer to a RawByteArray containing the key exchange payload
Remember to free both the RawByteArray and RawByteArray data
*/
RawByteArray *constructKexPayload();

/*
Input sock: socket to send the message
Returns: SOME ERROR CODE
*/
int sendProtocol(int sock);

/*
Input numBytes: the number of random bytes to generate
Returns a pointer to a RawByteArray struct that contains the random bytes and the length 
of the random bytes
Remember to free both the RawByteArray and RawByteArray data
*/
RawByteArray* generateRandomBytes(int numBytes);

/*
Input: the socket to send the message
Returns: SOME ERROR CODE
*/
int sendKexInit (int sock);

/*
Input ctx: an EVP cipher context that contains the encryption key and IV
Input message: the message to encrypt or decrypt
Input encrypt: 1 for encrypt mode, 0 for decrypt mode
Returns a pointer to a RawByteArray struct which contains the result of the encrypt/decrypt
operation
Remember to free both the RawByteArray and RawByteArray data
*/
RawByteArray *aes128EncryptDecrypt(EVP_CIPHER_CTX *ctx, RawByteArray *message, int encrypt);

/*
Input sock: the socket to send/receive encrypted data to/from
Input seqNum: the sequence number, used in computing MAC
Returns SOME ERROR CODE - update later
Control function for encryption and MAC messages (post DH messages)
seqNum is incremented implicitly in sendReceiveEncryptedData()
*/
int sendReceiveEncryptedData(int sock, uint32_t *seqNum);

/*
Input integrityKey: the integrity key used to compute MAC
Input packet: the packet to compute MAC of
Input sequenceNumber: the sequence number of the packet to compute MAC of
Returns a pointer to a RawByteArray struct which contains the MAC
Remember to free both the RawByteArray and RawByteArray data
*/
RawByteArray *computeHmacSha1(RawByteArray *integrityKey, RawByteArray *packet, uint32_t sequenceNumber);

/*
Input sock: the socket to send the protocol packet to
Returns: SOME ERROR CODES - NEED TO UPDATE
*/
int sendNewKeysPacket(int sock);

/*
Input sock: the socket to send the protocol packet to
Input encryptCtx: pointer to an OpenSSL encryption context (used to encrypt plaintext)
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Returns: SOME ERROR CODES - NEED TO UPDATE
*/
int sendServiceReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum);

/*
Input sock: the socket to send the protocol packet to
Input encryptCtx: pointer to an OpenSSL encryption context (used to encrypt plaintext)
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Returns: SOME ERROR CODES - NEED TO UPDATE
*/
int sendUserAuthReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum);

/*
Input mac: the computed MAC
Input ciphertext: the ciphertext to append the MAC to
Returns: pointer to a RawByteArray struct that contains the ciphertext and MAC
*/
RawByteArray *concatenateMacToMsg(RawByteArray *mac, RawByteArray *ciphertext);

/*
Input sock: the socket to send the protocol packet to
Input bufferSize: the size of the buffer in which to write the server's response
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Input decryptCtx: pointer to an OpenSSL decryption context (used to decrypt ciphertext)
Returns: 1 if MAC is valid, 0 if MAC is not valid
*/
int recvMsgVerifyMac(int sock, int bufferSize, RawByteArray *integrityKey, int seqNum, EVP_CIPHER_CTX *decryptCtx);

/*
Input sock: the socket to send the protocol packet to
Input encryptCtx: pointer to an OpenSSL encryption context (used to encrypt plaintext)
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Returns: SOME ERROR CODES - NEED TO UPDATE
*/
int sendChannelOpenReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum);

/*
Input sock: the socket to send the protocol packet to
Input encryptCtx: pointer to an OpenSSL encryption context (used to encrypt plaintext)
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Returns: SOME ERROR CODES - NEED TO UPDATE
*/
int sendChannelReq(int sock, EVP_CIPHER_CTX *encryptCtx, RawByteArray *integrityKey, uint32_t seqNum);

/*
Input sock: the socket to send the protocol packet to
Input bufferSize: the size of the buffer in which to write the server's response
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Input decryptCtx: pointer to an OpenSSL decryption context (used to decrypt ciphertext)
Returns: SOME ERROR CODES - NEED TO UPDATE
This function is hard coded to receive only the window adjust and channel success message
and verify the corresponding MACs. This function will be obselete once we implement
a dynamic solution to reading server responses
*/
int recvWinAdjChanSuccVerifyMac(int sock, int bufferSize, RawByteArray *integrityKey, int seqNum, EVP_CIPHER_CTX *decryptCtx);

/*
Input sock: the socket to send the protocol packet to
Input bufferSize: the size of the buffer in which to write the server's response
Input integrityKey: the integrity key, used to compute MAC
Input seqNum: the sequence number, used in computing MAC
Input decryptCtx: pointer to an OpenSSL decryption context (used to decrypt ciphertext)
Returns: 1 if both MACs are valid, 0 otherwise
This function dynamically reads the server response, but only for the channel data 
message. This function will also be obselete once we implement a dynamic solution to
reading server responses
*/
int recvChanDataVerifyMac(int sock, int bufferSize, RawByteArray *integrityKey, int seqNum, EVP_CIPHER_CTX *decryptCtx);