CC		:= gcc
CFLAGS		:= -Wall -O2 -I../..
RAGEL		:= ragel
TARGETS		:= uri-parse-speed

.PHONY: all test clean gen uri_parser

all: $(TARGETS)

gen:
	$(RAGEL) -s uri_parser.rl

uri_parser.c: uri_parser.rl uri_grammar.rl uri_parser.h
	$(RAGEL) -s uri_parser.rl

uri-parse-speed: uri_parser.c uri-parse-speed.c
	$(CC) $(CFLAGS) -o $@ $^

test: uri-parse-speed
	./uri-parse-speed < uri.txt

clean:
	rm -f $(TARGETS)
