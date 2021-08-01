# Makefile

include ../../makefile.inc

TARGETS		:= mod_http.so

.PHONY: all clean

all: $(TARGETS)

#mod_http.so: mod_http.o http11_parser.o http11_requests.o mph.o ../../lfq.o
mod_http.so: mod_http.o http11_parser.o http11_requests.o ../../mymdebug.o ../../lfq.o ../sigtran/sigtran_http_resp_func.o ../sigtran/map-dialog-mgmt.o ../sigtran/iarray.o ../sigtran/dialogue-utils.o ../sigtran/m3ua.o ../sigtran/sccp.o ../sigtran/map-utils.o ../sigtran/utils.o ../sigtran/llist.o ../sigtran/mytlv.o
	$(CC) $(CFLAGS) -shared -o $@ $^

mod_http.o: mod_http.c mod_http.h
	$(CC) $(CFLAGS) -fpic -c -o $@ mod_http.c

http11_parser.o: http11_parser.c http11_parser.h
	$(CC) $(CFLAGS) -fpic -c -o $@ http11_parser.c

http11_requests.o: http11_requests.c http11_requests.h
	$(CC) $(CFLAGS) -fpic -c -o $@ http11_requests.c

mph.o: mph.c mph.h
	$(CC) $(CFLAGS) -fpic -c -o $@ mph.c

%.c: %.rl
	$(RAGEL) -o $@ $^

clean:
	rm -f *.o $(TARGETS)
