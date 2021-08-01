# Makefile
CC		:= gcc
#OPT		:= /opt/local
OPT		:= $(LPATH)
PREFIX		:= $(OPT)
CFLAGS		:= -Wall -O2 -fpic -I$(PREFIX)/include/asn1c -I$(PREFIX)/include -I../include
# Linking not done, so LDFLAGS not needed
LDFLAGS		:=
TARGETS		:= libosmo-asn1-tcap.so
SRCS		:= $(wildcard *.c)
OBJS		:= $(patsubst %.c,%.o,$(SRCS))

all: $(TARGETS)

libosmo-asn1-tcap.so: $(OBJS)
	$(CC) $(CFLAGS) -shared -o $@ $^

clean:
	rm -f *.o $(TARGETS)
