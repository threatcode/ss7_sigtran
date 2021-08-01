# makefile.inc
# vim: set filetype=make
# Makefile for inclusion from Makefile
#CFLAGS		:= -g -Wall -O2 -ansi -D_REENTRANT -pthread -DNWORKERS=4
#CFLAGS		+= -I/usr/local/include/tcap
# Makefile
CC		:= gcc
OPT		:= /opt/local
SRCROOT		:= /ntss7
#CFLAGS		:= -Wall -O2 -D_REENTRANT -pthread -DNWORKERS=4 -I. $(shell pkg-config --cflags cmph)
CFLAGS		:= -Wall -O2 -D_REENTRANT -pthread -DNWORKERS=4 -I. -I$(SRCROOT)/ayubd-ng
# CURL SSL part has memory leak issue (maybe, as I read online)
#CFLAGS		:= -DUSE_CURL_SSL
# Debugging/trace of execution of the daemon
CFLAGS		+= -g
CFLAGS		+= -DDEBUG
# shows time (in microseconds) from beginning of receiving a request and after sending a response
# a diff to the two values will give you time taken to serve the request
#CFLAGS		+= -DTIMETRACE
# Testing purpose, no url call to app_url is made, a fixed response is returned
#CFLAGS		+= -DUGWTEST
# Memory debugging with my own custom routines
#CFLAGS		+= -DMYMDEBUG
# Memory debugging with dmalloc package
#CFLAGS		+= -DDMALLOC -DDMALLOC_FUNC_CHECK
#CFLAGS		+= -DDMALLOC
#CFLAGS		+= -DTCMALLOC
# Enable returning partially parsed TCAP packet, useful for freeing tid with problematic packets
CFLAGS		+= -DTCAP_PARTIAL
CFLAGS		+= -g
#CFLAGS		+= -DMTRACE
CFLAGS		+= -I/usr/local/include
CFLAGS		+= -I/opt/local/include
CFLAGS		+= -I$(OPT)/osmo/include
CFLAGS		+= -I$(OPT)/osmo/include/asn1c
CFLAGS		+= -I$(OPT)/osmo/include/tcap
CFLAGS		+= -I$(OPT)/osmo/include/map
LDFLAGS		:= -lm -ldl
LDFLAGS		+= -lsctp
#LDFLAGS		+= -lcurl
LDFLAGS		+= -L/opt/local/lib -lJudy
LDFLAGS		+= -L$(OPT)/osmo/lib -losmocore -losmogsm -losmogsm-milenage -lasn1c
#LDFLAGS		+= -L$(HOME)/osmo/lib -losmocore -lasn1c -lm
LDFLAGS		+= -losmo-asn1-tcap
LDFLAGS		+= -losmo-asn1-map
#LDFLAGS		+= -ldmallocth
#LDFLAGS		+= -ltcmalloc
RAGEL		:= ragel

