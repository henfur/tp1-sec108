CC = gcc -lpthread
SCANNER_SRC = src/scanner.c
CLIENT_SRC = src/client.c
CLIENT-HTTP_SRC = src/client-http.c

all: scanner

scanner: $(SCANNER_SRC)
	$(CC) -o bin/scanner $(SCANNER_SRC)

client: $(CLIENT_SRC)
	$(CC) -o bin/client $(CLIENT_SRC)

client-http: $(CLIENT-HTTP_SRC)
	$(CC) -o bin/client-http $(CLIENT-HTTP_SRC)

clean:
	rm bin/*