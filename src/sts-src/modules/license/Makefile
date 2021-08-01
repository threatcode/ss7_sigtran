# Makefile

include ../../makefile.inc


TARGETS		:= mod_license.so

.PHONY: all clean

all: $(TARGETS)

mod_license.so: mod_license.o ../../mymdebug.o
	$(CC) $(CFLAGS) -shared -o $@ $^

mod_license.o: mod_license.c mod_license.h
	$(CC) $(CFLAGS) -fpic -c -o $@ mod_license.c

clean:
	rm -f *.o $(TARGETS)
