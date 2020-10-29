.PHONY: all clean
CC = g++
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -pedantic

EXECUTABLE = sslsniff

all: $(EXECUTABLE)

sslsniff: $(EXECUTABLE).o
	$(CC) -o $@ $^ -lpcap

sslsniff.o: $(EXECUTABLE).cpp
	$(CC) -c $^

zip:
	zip $(EXECUTABLE).zip *.c *.h Makefile

clean:
	rm -rf $(EXECUTABLE) *.o