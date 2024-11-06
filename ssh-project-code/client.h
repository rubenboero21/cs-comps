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
Input: The socket to send the protocol packet to
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

// ADD MAC FUNCTION ONCE ITS WORKING

// ADD ENCRYPT/DECRYPT FUNCTION