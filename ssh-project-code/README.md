# README

**client.c**

Written by Liam and Ruben for Fall CS Comps with Jeff Ondich
    
Client.c is a simple ssh client.


**How to use the Makefile:**
- Just compile the code:
'''make
make compile
'''
- Compile and run the code:
'''make
make ARGS="<hostname> <port number>"
'''
ie: '''make
make ARGS="192.168.64.6 22"
'''
- Clean up created files:
'''make
make clean
'''