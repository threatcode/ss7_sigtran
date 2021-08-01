/*
 * utils.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"
#include <unistd.h>
#include <Judy.h>

/* hex2bin/hexdump routines */
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif


void hexdump(void *mem, size_t len)
{
  unsigned int i = 0, j = 0;

  for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
    /* print offset */
    if (i % HEXDUMP_COLS == 0) {
      printf("0x%06x: ", i);
    }

    /* print hex data */
    if (i < len) {
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    } else { /* end of block, just aligning for ASCII dump */
      printf("   ");
    }

    /* print ASCII dump */
    if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
      for (j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
	if (j >= len) { /* end of block, not really printing */
	  putchar(' ');
	} else if(isprint(((char*)mem)[j])) { /* printable char */
	  putchar(0xFF & ((char*)mem)[j]);        
	} else { /* other char */
	  putchar('.');
	}
      }
      putchar('\n');
    }
  }
}

octet *hex2bin(octet *hex, uint16_t len)
{
  octet *ret = NULL;
  uint16_t count = 0;
  if (len % 2 != 0) return NULL; /* not even number of hex chars */

  len = len / 2;
  ret = MYCALLOC(1, len);

  for (count = 0; count < len; count++) {
    sscanf((char *) hex, "%2hhx", &ret[count]);
    hex += 2;
  }

  return ret;
}

/*
 * http://www.linuxjournal.com/article/9784?page=0,1
 */
/* sctp utility functions */
sctp_assoc_t sctp_address_to_associd(int sock_fd, struct sockaddr *sa, socklen_t salen)
{ 
  //struct sctp_paddrparams sp = { 0 }; // spec has changed
  struct sctp_paddrinfo sp = { 0 };
  socklen_t siz = 0;

  //siz = sizeof(struct sctp_paddrparams); // the spec has changed
  siz = sizeof(struct sctp_paddrinfo);
  memset(&sp, 0, siz);
  //memcpy(&sp.spp_address, sa, salen);
  memcpy(&sp.spinfo_address, sa, salen);
  sctp_opt_info(sock_fd, 0, SCTP_GET_PEER_ADDR_INFO, &sp, &siz);
  //return(sp.spp_assoc_id);
  return(sp.spinfo_assoc_id);
}


int sctp_get_no_strms(int sock_fd,struct sockaddr *to, socklen_t tolen)
{
  socklen_t retsz = 0;
  struct sctp_status status = { 0 };

  retsz = sizeof(status);	
  memset(&status,0, sizeof(status));

  status.sstat_assoc_id = sctp_address_to_associd(sock_fd,to,tolen);
  getsockopt(sock_fd,IPPROTO_SCTP, SCTP_STATUS,
      &status, &retsz);
  return(status.sstat_outstrms);
}

int sigtran_send_ASPUP(sigtran_t *s)
{
  octet *oct = NULL;
  ssize_t nw = 0;
  uint32_t nextpos = 0;

  oct = m3ua_octet_ASPUP(&nextpos);
  if (!oct) {
    CRITICAL("ASPUP packet not created!!! System may not function properly.\n");
    s->aspup_sent = 0;
  } else {
    CRITICAL("Sending ASPUP\n");
    if ((nw = sctp_sendmsg(s->fd, oct, nextpos, (struct sockaddr *) &s->servaddr, s->addrlen, s->ppid, 0, s->mgmt_str_no, 0, 0)) != nextpos) {
      CRITICAL("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nw);
      s->aspup_sent = 0;
    } else {
      s->aspup_sent = 1;
    }
    MYFREE(oct);
  }

  return s->aspup_sent;
}

/*
 *  * Given an event notification, print out what it is.
 *  return -1 to notify fatal error notification, application should quit
 *  return 0 to notify and return normally
 *   */
int sctp_handle_notification(sigtran_t *s, void *buf)
{
  struct sctp_assoc_change *sac;
  struct sctp_send_failed  *ssf;
  struct sctp_paddr_change *spc;
  struct sctp_remote_error *sre;
  struct sctp_adaptation_event *sai;
  union sctp_notification  *snp;
  char    addrbuf[INET_ADDRSTRLEN];
  const char   *ap = NULL;
  struct sockaddr_in  *sin = NULL;
  int ret = 0;

  snp = buf;

  switch (snp->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE:
      sac = &snp->sn_assoc_change;
      CRITICAL("^^^ assoc_change: state=%hu, error=%hu, instr=%hu "
	  "outstr=%hu\n", sac->sac_state, sac->sac_error,
	  sac->sac_inbound_streams, sac->sac_outbound_streams);

      if (!s->aspup_sent) {
	sigtran_send_ASPUP(s);
      } else {
	if (sac->sac_error != 0) {
	  ret = -1;
	  s->aspup_sent = 0; /* so that we resend it */
	}
      }
      break;
    case SCTP_SEND_FAILED:
      ret = -1;
      ssf = &snp->sn_send_failed;
      CRITICAL("^^^ send_failed: len=%hu err=%d\n", ssf->ssf_length,
	  ssf->ssf_error);
      break;
    case SCTP_PEER_ADDR_CHANGE:
      spc = &snp->sn_paddr_change;
      if (spc->spc_aaddr.ss_family == AF_INET) {
	sin = (struct sockaddr_in *)&spc->spc_aaddr;
	ap = inet_ntop(AF_INET, &sin->sin_addr, addrbuf,
	    INET_ADDRSTRLEN);
      }
      CRITICAL("^^^ intf_change: %s state=%d, error=%d\n", ap,
	  spc->spc_state, spc->spc_error);
      break;
    case SCTP_REMOTE_ERROR:
      ret = -1;
      sre = &snp->sn_remote_error;
      CRITICAL("^^^ remote_error: err=%hu len=%hu\n",
	  ntohs(sre->sre_error), ntohs(sre->sre_length));
      break;
    case SCTP_SHUTDOWN_EVENT:
      ret = -1;
      CRITICAL("^^^ shutdown event\n");
      break;
    case SCTP_ADAPTATION_INDICATION:
      sai = &snp->sn_adaptation_event;
      CRITICAL("^^^ adaptation layer indication: len=%hu type=%hu\n", sai->sai_length,
	  sai->sai_type);
      break;
    default:
      CRITICAL("^^^ unknown notification type: %hu\n", snp->sn_header.sn_type);
      break;
  }

  return ret;
}



#if 0
void sctp_echo_cli(FILE *fp, int sock_fd, struct sockaddr *to, socklen_t tolen)
{
  int msg_flags = 0;
  char sendline[512] = { 0 }, recvline[512] = { 0 };
  struct sockaddr_in peeraddr = { 0 };
  struct sctp_sndrcvinfo sri = { 0 };
  socklen_t len = 0;
  size_t out_sz = 0;
  int rd_sz = 0;

  memset(&sri, 0, sizeof(sri));
  while (fgets(sendline, sizeof(sendline), fp)) {
    out_sz = strlen(sendline);
    sctp_sendmsg(sock_fd, sendline, out_sz, (struct sockaddr *) to, tolen, 0, 0, 0, 0, 0);

    len = sizeof(peeraddr);
    rd_sz = sctp_recvmsg(sock_fd, recvline, sizeof(recvline), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
    printf("From str:%d seq:%d (assoc:0x%x):",
	sri.sinfo_stream, sri.sinfo_ssn, (u_int) sri.sinfo_assoc_id);
    printf("%.*s", rd_sz, recvline);
  }
}
#endif

uint8_t bcd2dec(uint8_t bcd)
{
  return (((bcd & 0xf0) >> 4) * 10) + (bcd & 0x0f);
}

uint8_t dec2bcd(uint8_t dec)
{
  return (((dec / 10) << 4) | (dec % 10));
}

/* Converts a hex character to its integer value */
static char from_hex(char ch) {
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *rawurlencode(const char *str, size_t len, size_t *nextpos)
{
  const char *pstr = str;
  char *buf = MYCALLOC(1, len * 3 + 1);
  char *pbuf = buf;

  *nextpos = 0;
  while (*pstr) {
    if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
      *pbuf++ = *pstr;
      *nextpos += 1;
    } else {
      *pbuf++ = '%';
      *pbuf++ = to_hex(*pstr >> 4);
      *pbuf++ = to_hex(*pstr & 15);
      *nextpos += 3;
    }
    pstr++;
  }
  *pbuf = '\0';
  *nextpos += 1; /* include the length of the NUL byte */
  return buf;
}


/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *rawurldecode(const char *str, size_t len, size_t *nextpos)
{
  const char *pstr = str;
  char *buf = MYCALLOC(1, len + 1); /* in worst case the whole string may be the same as encoded */
  char *pbuf = buf;

  if (nextpos) *nextpos = 0;
  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
	*pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
	if (nextpos) *nextpos += 1;
	pstr += 2;
      }
    } else if (*pstr == '+') { 
      *pbuf++ = ' ';
      if (nextpos) *nextpos += 1;
    } else {
      *pbuf++ = *pstr;
      if (nextpos) *nextpos += 1;
    }
    pstr++;
  }
  *pbuf = '\0';

  if (nextpos) *nextpos += 1;

  return buf;
}


#if 0
int tcp_connect(const char *addr, uint16_t port)
{
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  if (inet_pton(AF_INET, addr, &servaddr.sin_addr) <= 0) {
    perror("inet_pton: servaddr");
    return -1;
  }

#ifdef __linux__
  int type = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
#else
  int type = SOCK_STREAM;
#endif
  int proto = 0;

  int sockfd = socket(AF_INET, /* family */
      type, /* type */
      proto); /* protocol */
  if (sockfd == -1) {
    perror("socket");
    return -1;
  }


  if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) {
    perror("connect");
    close(sockfd);
    return -1;
  }

  return sockfd;
}

int tcp_close(int fd)
{
  return close(fd);
}
#endif

static const char bcd_num_digits[] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '*', '#', 'a', 'b', 'c', '\0'
};

char *decode_called_party(const uint8_t *src, uint8_t len, char *outbuf, uint8_t *nextpos)
{
  int i;
  int k = 0;
  uint8_t u = 0, l = 0;
  if (nextpos) *nextpos = 0;

  for (i = 0; i < len; ++i) {
    l = src[i] & 0x0f;
    u = (src[i] & 0xf0) >> 4;
    outbuf[k++] = bcd_num_digits[l];
    outbuf[k++] = bcd_num_digits[u];
    //fprintf(stderr, "%u%u", l, u);
  }
  /* check if we already put '\0' at the end */
  if (outbuf[k-1] != '\0') {
    outbuf[k] = '\0';
    if (nextpos) *nextpos = k;
  } else {
    //fprintf(stderr, "Already put NUL\n");
    if (nextpos) *nextpos = k - 1;
  }

  return outbuf;
}

uint8_t *encode_called_party(const char *src, uint8_t len, uint8_t *outbuf, uint8_t *nextpos)
{
  int i = 0;
  int k = 0;
  char u = 0, l = 0;
  if (nextpos) *nextpos = 0;
  //uint8_t maxbuf = 6; /* FIXME: in future versions it should be fixed to be flexible */
  uint8_t maxbuf = 7; /* FIXME: in future versions it should be fixed to be flexible */

  for (i = 0; (i < len) && ((len - i) != 1); i += 2) {
    l = src[i] - '0';
    u = src[i+1] - '0';
    outbuf[k++] = (u << 4) | l;
    if (k > maxbuf) break;
  }
  if ((len -i) == 1) {
    l = src[i] - '0';
    u = 0x0f; /* pad with all 1 */
    outbuf[k++] = (u << 4) | l;
  }
  if (nextpos) *nextpos = k;

  return outbuf;
}

char *decode_msisdn(const uint8_t *src, uint8_t len, char *outbuf, uint8_t *nextpos)
{
  int i = 0;
  int k = 0;
  uint8_t u = 0, l = 0;
  if (nextpos) *nextpos = 0;

  for (i = 1; i < len; ++i) { /* first byte is extension info */
    l = src[i] & 0x0f;
    u = (src[i] & 0xf0) >> 4;
    outbuf[k++] = bcd_num_digits[l];
    outbuf[k++] = bcd_num_digits[u];
    //fprintf(stderr, "%u%u", l, u);
  }
  /* check if we already put '\0' at the end */
  if (outbuf[k-1] != '\0') {
    outbuf[k] = '\0';
    if (nextpos) *nextpos = k;
  } else {
    //fprintf(stderr, "Already put NUL\n");
    if (nextpos) *nextpos = k - 1;
  }

  return outbuf;
}

uint8_t *encode_msisdn(const char *src, uint8_t len, uint8_t *outbuf, uint8_t *nextpos)
{
  int i = 0;
  int k = 0;
  char u = 0, l = 0;
  if (nextpos) *nextpos = 0;

  outbuf[k++] = 0x91; /* (Extension: No Extension; Nature of Number: International Number; Number plan: ISDN/Telephony Numbering) */
  for (i = 0; (i < len) && ((len - i) != 1); i += 2) { /* first byte is extension info */
    l = src[i] - '0';
    u = src[i+1] - '0';
    outbuf[k++] = (u << 4) | l;
  }
  if ((len -i) == 1) {
    l = src[i] - '0';
    u = 0x0f; /* pad with all 1 */
    outbuf[k++] = (u << 4) | l;
  }
  if (nextpos) *nextpos = k;

  return outbuf;
}
