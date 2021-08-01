/*
 * utils.h
 */
#ifndef _UTILS_H_
#define _UTILS_H_

#include "defs.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <netinet/tcp.h>
#include "llist.h"
#if 0
#include "kv.h"
#endif

#include "mod_sigtran.h"

void hexdump(void *mem, size_t len);
octet *hex2bin(octet *hex, uint16_t len);

sctp_assoc_t sctp_address_to_associd(int sock_fd, struct sockaddr *sa, socklen_t salen);
int sctp_get_no_strms(int sock_fd,struct sockaddr *to, socklen_t tolen);
int sctp_handle_notification(sigtran_t *s, void *buf);
//void sctp_echo_cli(FILE *fp, int sock_fd, struct sockaddr *to, socklen_t tolen);
uint8_t bcd2dec(uint8_t bcd);
uint8_t dec2bcd(uint8_t dec);
char *decode_called_party(const uint8_t *src, uint8_t len, char *outbuf, uint8_t *nextpos);
uint8_t *encode_called_party(const char *src, uint8_t len, uint8_t *outbuf, uint8_t *nextpos);
char *decode_msisdn(const uint8_t *src, uint8_t len, char *outbuf, uint8_t *nextpos);
uint8_t *encode_msisdn(const char *src, uint8_t len, uint8_t *outbuf, uint8_t *nextpos);
char *rawurlencode(const char *str, size_t len, size_t *nextpos);
#if 0
int tcp_connect(const char *addr, uint16_t port);
#endif
char *rawurldecode(const char *str, size_t len, size_t *nextpos);
int gsm_7bit_decode(char *dst, const octet *src, uint8_t len);
int gsm_7bit_encode(uint8_t *dst, const char *src);

#endif
