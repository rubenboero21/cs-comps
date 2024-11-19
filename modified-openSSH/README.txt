Liam and I modified the following files from OpenSSH version openssh-9.9p1 to aid in 
our debugging. The modified sections of the code begin with a comment including "HIJACK", 
and end with "END" or "END HIJACK". We got the code from the OpenSSH GitHub: 
https://github.com/openssh/openssh-portable

Files modified
    kexdh.c - called when our client connects to it & we get print out of K
            - handles generation of K
            - hashes the exchange message
            - prints shared secret, computed key size, and public key
    kex.c - called when our client connects - printing exchange hash and session ID
            - hash is printed out from the function that is doing encryption stuff (I think)
                (kex_derive_keys function)
    kexgen.c - prints out the exchange message components
    mac.c - printing out info about MAC: key, sequence number, packet info
          - printing sequence number and server unencrypted packet in mac_check
    packet.c 
        - printing packet len and encrypted packet in ssh_packet_process_incoming()
        - ssh_packet_read_poll2() decrypts and does verification
    cipher.c
        - printing cipher context init information
        - Cipher name, encryption mode, key, IV
