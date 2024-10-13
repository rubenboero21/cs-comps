# CFLAGS = -Wall
# If we want to use a library to help with DH, need to include it in compile command:
# this will only work for Ruben's setup, need to change paths to match your installation of openssl
CFLAGS = -Wall -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

# Compile and run the program
run: a.out
	./a.out $(ARGS)

# Just compile the program
compile: a.out

# Rule for creating the executable
a.out: client.c
	gcc $(CFLAGS) -o a.out client.c

# Clean up the generated files
clean:
	rm -f a.out
