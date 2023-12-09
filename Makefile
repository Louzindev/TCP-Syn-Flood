C_SOURCE_FILES:=$(wildcard *.c)
EXE_FILES:=$(patsubst %.c,%.exe,$(C_SOURCE_FILES))
CC=gcc
CFLAGS=-Wall -pthread

all: clean $(EXE_FILES)

%.exe: %.c
	$(CC) $< $(CFLAGS) -o $@ 

clean:
	rm -f $(EXE_FILES)