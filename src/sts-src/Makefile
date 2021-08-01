# Makefile
# written by Ayub <mrayub@gmail.com>
# vim: sw=2


include makefile.inc

TARGETS		:= stgw
MODULES		:= license signal sigtran http

.PHONY: all clean install lib

all: $(TARGETS)

stgw: lfq.o main.o mymdebug.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	for mod in $(MODULES); do pushd modules/$$mod; make all; popd; done

lfq-test: lfq.o lfq-test.c 
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

main.o: main.h main.c poll.h
	$(CC) $(CFLAGS) -c -o $@ main.c

lfq.o: lfq.h lfq.c
	$(CC) $(CFLAGS) -fpic -c -o $@ lfq.c

mymdebug.o: mymdebug.h mymdebug.c
	$(CC) $(CFLAGS) -fpic -c -o $@ mymdebug.c

config: config.c config.h
	$(CC) $(CFLAGS) -o $@ config.c ext-lib/ini_parser/minIni.c

install:
	./install.sh

clean:
	rm -f *.o $(TARGETS)
	for mod in $(MODULES); do pushd modules/$$mod; make clean; popd; done

lib:
	pushd lib; make; popd
