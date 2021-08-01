# Makefile

include ../../makefile.inc

TARGETS		:= mod_signal.so

.PHONY: all clean

all: $(TARGETS)

mod_signal.so: mod_signal.o ../../mymdebug.o
	$(CC) $(CFLAGS) -shared -o $@ $^

mod_signal.o: mod_signal.c mod_signal.h
	$(CC) $(CFLAGS) -fpic -c -o $@ mod_signal.c

clean:
	rm -f *.o $(TARGETS)
