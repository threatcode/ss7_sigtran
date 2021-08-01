# Makefile

include ../../makefile.inc


#TARGETS		:= mod_sigtran.so sigtran_http_resp_func.o echo_sctpserver echo_sctpclient mytlv-test llist-test m3ua-test map-test test iarray-test msisdn-test dialogue-test url-test t_mtrace utils-test map-utils-test
TARGETS		:= mod_sigtran.so sigtran_http_resp_func.o
#TARGETS		:= mod_sigtran.so

.PHONY: all clean

all: $(TARGETS)

#mod_sigtran.so: mod_sigtran.o ../../lfq.o utils.o sigtran_tcap.o tcap.o sccp.o m3ua.o mytlv.o llist.o kv.o iarray.o dialogue-utils.o uri-utils.o map-dialog-mgmt.o map-utils.o
mod_sigtran.so: mod_sigtran.o ../../mymdebug.o ../../lfq.o utils.o sigtran_tcap.o tcap.o sccp.o m3ua.o mytlv.o llist.o iarray.o dialogue-utils.o uri-utils.o map-dialog-mgmt.o map-utils.o uri_parser.o
	$(CC) $(CFLAGS) -shared -o $@ $^

mod_sigtran.o: mod_sigtran.c mod_sigtran.h
	$(CC) $(CFLAGS) -fpic -c -o $@ mod_sigtran.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -fpic -c -o $@ utils.c

tcap.o: tcap.c tcap.h
	$(CC) $(CFLAGS) -fpic -c -o $@ tcap.c

sccp.o: sccp.c sccp.h
	$(CC) $(CFLAGS) -fpic -c -o $@ sccp.c

m3ua.o: m3ua.c m3ua.h
	$(CC) $(CFLAGS) -fpic -c -o $@ m3ua.c

mytlv.o: mytlv.c mytlv.h
	$(CC) $(CFLAGS) -fpic -c -o $@ mytlv.c

llist.o: llist.c llist.h
	$(CC) $(CFLAGS) -fpic -c -o $@ llist.c

uri_parser.o: uri_parser.c uri_parser.h
	$(CC) $(CFLAGS) -fpic -c -o $@ uri_parser.c

kv.o: kv.c kv.h
	$(CC) $(CFLAGS) -fpic -c -o $@ kv.c

crc.o: crc.c crc.h
	$(CC) $(CFLAGS) -fpic -c -o $@ crc.c

sigtran_tcap.o: sigtran_tcap.c sigtran_tcap.h
	$(CC) $(CFLAGS) -fpic -c -o $@ sigtran_tcap.c

sigtran_http_resp_func.o: sigtran_http_resp_func.c
	$(CC) $(CFLAGS) -fpic -c -o $@ sigtran_http_resp_func.c

gsm.o: gsm.c gsm.h
	$(CC) $(CFLAGS) -fpic -c -o $@ gsm.c

iarray.o: iarray.c iarray.h
	$(CC) $(CFLAGS) -fpic -c -o $@ iarray.c

dialogue-utils.o: dialogue-utils.c dialogue-utils.h
	$(CC) $(CFLAGS) -fpic -c -o $@ dialogue-utils.c

map-dialog-mgmt.o: map-dialog-mgmt.c map-dialog-mgmt.h
	$(CC) $(CFLAGS) -fpic -c -o $@ map-dialog-mgmt.c

map-utils.o: map-utils.c map-utils.h
	$(CC) $(CFLAGS) -fpic -c -o $@ map-utils.c

uri-utils.o: uri-utils.c uri-utils.h
	$(CC) $(CFLAGS) -fpic -c -o $@ uri-utils.c

iarray-test: iarray-test.c iarray.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

mytlv-test: mytlv-test.c mytlv.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tcap-test: tcap-test.c tcap.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

map-test: map-test.c utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

echo_sctpserver: echo_sctpserver.c utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

echo_sctpclient: echo_sctpclient.c utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

llist-test: llist-test.c llist.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

m3ua-test: m3ua-test.c m3ua.o llist.o mytlv.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

crc-test: crc-test.c crc.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

msisdn-test: msisdn-test.c utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

dialogue-test: dialogue-test.c dialogue-utils.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

uri-test: uri-test.c uri-utils.o uri_parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

t_mtrace: t_mtrace.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

utils-test: utils-test.c utils.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

map-utils-test: map-utils-test.c map-utils.o utils.o gsm.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: test.c gsm_utils.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(TARGETS)
