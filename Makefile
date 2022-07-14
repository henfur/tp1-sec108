CC = gcc
LIB = src/lib.c
SCANNER_SRC = src/scanner.c

all: scanner

scanner: $(SCANNER_SRC) $(LIB)
	$(CC) -o bin/scanner $(SCANNER_SRC) $(LIB)

clean:
	rm bin/*