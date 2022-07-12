CC = gcc
LIB = src/lib.c
SCANNER_SRC = src/scanner.c
CLIENT_SRC = src/client.c

all: client

# scanner: $(SCANNER_SRC) $(LIB)
# 	$(CC) -o bin/scanner $(SCANNER_SRC) $(LIB)

client: $(CLIENT_SRC) $(LIB)
	$(CC) -o bin/client $(CLIENT_SRC) $(LIB)

clean:
	rm bin/*