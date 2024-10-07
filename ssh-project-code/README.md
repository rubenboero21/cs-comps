# README

**client.c**

Written by Liam and Ruben for Fall CS Comps with Jeff Ondich
    
client.c is a simple ssh client that runs on the command line. 


**How to use the Makefile:**

Just compile the code:
```makefile
make compile
```
Compile and run the code:
```makefile
make ARGS="<hostname> <port number>"
```
Example:
```makefile
make ARGS="192.168.64.6 22"
```
Clean up created files:
```makefile
make clean
```