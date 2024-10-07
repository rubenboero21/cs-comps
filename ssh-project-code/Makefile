CFLAGS = -Wall

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
