C_FILES = $(wildcard *.c crypto/*.c b64/*.c)
O_FILES = $(C_FILES:%.c=%.o)

CC=gcc
CFLAGS=-std=c23 -fPIC -pedantic -fstack-clash-protection -fomit-frame-pointer -Wall -Wextra 

libbwt.so: $(O_FILES)
	$(CC) $(CFLAGS) -Wl,-rpath=. -shared -o $@ $^ -lssl -lcrypto 
	
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(O_FILES)
	rm -f libbwt.so
