CC=gcc
CFLAGS=-Wall
OBJ=rcfs.o lzo1x_decompress.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

rcfs: $(OBJ)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

.PHONY: clean

clean:
	rm -rf rcfs *.o
