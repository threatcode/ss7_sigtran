/*
 * mod_http.h
 * keep-alive keeps keep-alive enabled clients happy and performs well too
 */
#ifndef __MOD_HTTP_H__
#define __MOD_HTTP_H__

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <time.h>		/* time_t, time(2), etc. */
#include <sys/uio.h>		/* writev(2), struct iovec, etc. */
#include <http11_parser.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "defs.h"
#include "module.h"
#include "mymdebug.h"

#include "http11_requests.h"

#ifndef HTTP_PORT
#define HTTP_PORT 9999
#endif

#ifndef HTTP_ADDR
#define HTTP_ADDR "127.0.0.1"
#endif

#ifndef HTTP_KEEPALIVE_TIMEOUT
#define HTTP_KEEPALIVE_TIMEOUT 15	/* seconds */
#endif

/* 's' must NOT have any side effects */
#define HTTP_VERIFY_METHOD(s,l) ((l) >=3 && (*(s) == 'G' && *((s)+1) == 'E' && *((s)+2) == 'T') ? __K__ : ERROR)
/* strcmp() version is slower than above */
/* #define VERIFY_METHOD(s) (strcmp(s, "GET") == 0 ? __K__ : ERROR) */


#define MAX_HEADERS 100		/* maximum number of headers allowed */
typedef struct {
  uint8_t keyidx;
  char *value;
} http_header_t;


/* return -1 in case of failure */
typedef size_t (*resp_func_t)(void *sys, const char *request_path, const char *query_string, char *resp_body, size_t resp_body_len);

typedef struct {
  state_t *state; /* allocate (only if needed, using state_new() */
  struct iovec iov[2];
  size_t iov0_pos;
  size_t iov1_pos;
  size_t iov0_len;
  size_t iov1_len;
  time_t heartbeat;
  int initialized;
  uint8_t header_loc[MAX_HEADERS]; /* header locations */
  char *header_val[MAX_HEADERS];

  /* quick hack to make it work only for USSD MT.
   * better engineering is needed to make it more reobust
   */
  resp_func_t resp_func; /* sigtran function to invoke, to handle the request */
  /* currently we support only GET. Later will support other features */
  char request_path[512]; /* query string */
  size_t request_path_len;
  char query_string[512]; /* query string */
  size_t query_string_len;
  char http_version[10]; /* requested HTTP version, should be same in reply */
  size_t http_version_len;
} http_session_data_t;

#include "sigtran_bridge.h"


typedef hook_t http_session_t;

#define http_session_new(hs,sys,fd) do {			\
  hs = lfq_dequeue((sys)->fq[fd%(sys)->nworkers]);		\
  if (!hs) hs = hook_new();					\
} while (0)

#if 0
#define http_session_new() hook_new()
#endif
#define http_session_data_new() MYCALLOC(1, sizeof(http_session_data_t))
#define http_session_free(s,sys) do {				\
  if (s) {							\
    int x = (s)->fd % (sys)->nworkers;				\
    (s)->fd = 0;						\
    (s)->ready = NULL;						\
    (s)->process = NULL;					\
    http_session_data_t *sd = (s)->data;			\
    if (sd) {							\
      if (sd->state) memset(sd->state, 0, sizeof(state_t));	\
      sd->iov0_pos = sd->iov1_pos = 0;				\
    }								\
    lfq_enqueue(((system_t *) (sys))->fq[x], (s));		\
  }								\
} while (0)

#define http_session_free_real(s) do {				\
  if (s) {							\
    http_session_data_t *sd = (s)->data;			\
    if (sd) {							\
      if ((sd)->state) MYFREE((sd)->state);			\
      if ((sd)->iov[0].iov_base) MYFREE((sd)->iov[0].iov_base);	\
      if ((sd)->iov[1].iov_base) MYFREE((sd)->iov[1].iov_base);	\
      MYFREE(sd);							\
    }								\
    MYFREE(s);							\
  }								\
} while (0)

#define http_session_close(s,sys) do {				\
  close((s)->fd);						\
  http_session_free(s,sys);					\
} while (0)

#if 0
#define http_session_close(s) do {				\
  close((s)->fd);						\
  http_session_data_t *sd = (http_session_data_t *) (s)->data;	\
  if (sd) {							\
    if ((sd)->state) { MYFREE((sd)->state); sd = NULL; }		\
    if ((sd)->iov[0].iov_base) MYFREE((sd)->iov[0].iov_base);	\
    if ((sd)->iov[1].iov_base) MYFREE((sd)->iov[1].iov_base);	\
    MYFREE(sd);							\
  }								\
  MYFREE(s);							\
} while (0)
#endif

#if 0
/* caller must free the decoded value */
static char *rawurldecode(const char *url)
{
  if (!url || *url == '\0')
    return NULL;

  size_t len = strlen(url);
  char *decoded = MYMALLOC(len+1);
  char *tmp = decoded;
  char x, y;

  while(*url) {
    if (*url != '%') {
      *tmp++ = *url++;
    } else if (*(url+1) && *(url+2)) {
      url++;
      x = *url++;
      y = *url++;
      *tmp++ = HEXCHARVAL(x) * 16 + HEXCHARVAL(y);
    } else {
      *tmp++ = *url++;
    }
  }

  *tmp = '\0';

  return decoded;
}
#endif

#if 0
static void http_elem_cb(void *data, const char *at, size_t len)
{
  DUMP(at,len);
  return;
}
#endif


#ifndef HTTP_MAXHEADER
#define HTTP_MAXHEADER 2048
#endif

#if 0
static char hr_about_iov1[] = "Developed and Maintained by Ayub <ayub@nixtecsys.com>, Nixtec Systems";
#endif

#if 0
static char hr_about_iov1[] = "Welcome";
#define hr_about_iov1_len (sizeof(hr_about_iov1)-1)
static char hr_about_iov0[] = "HTTP/1.1 200 OK\r\n" \
"Server: aws/0.9\r\n" \
"Content-Length: 7\r\n" \
"Connection: keep-alive\r\n" \
"Content-Type: text/plain\r\n\r\n";
#define hr_about_iov0_len (sizeof(hr_about_iov0)-1)
#define HTTP_RESPONSE_ABOUT_IOV0_LEN LEN(HTTP_RESPONSE_ABOUT_IOV0)

#define HTTP_RESPONSE "HTTP/1.1 200 OK\r\n" \
"Server: aws/0.9\r\n" \
"Content-Length: 12\r\n" \
"Connection: keep-alive\r\n" \
"Content-Type: text/plain\r\n\r\n" \
"Hello World!"
#define HTTP_RESPONSE_LENGTH sizeof(HTTP_RESPONSE)
#endif

#define HTTP_SERVER_VER "aws/0.9"
#define HTTP_RESP_HDR_FMT "%s 200 OK\r\n" \
"Server: " HTTP_SERVER_VER "\r\n" \
"Content-Length: %ld\r\n" \
"Connection: keep-alive\r\n" \
"Content-Type: text/plain\r\n\r\n"

#ifdef DEBUG
#define DUMP(at,len) do { fprintf(stderr, "%s\n", __func__); write(STDERR_FILENO, at, len); write(STDERR_FILENO, "\n", 1); } while (0)
#define DUMPX(field,flen,value,vlen) do { fprintf(stderr, "%s\n", __func__); write(STDERR_FILENO, field, flen); write(STDERR_FILENO, "\n", 1); write(STDERR_FILENO, value, vlen); write(STDERR_FILENO, "\n", 1); } while (0)
#else
#define DUMP(at,len)
#define DUMPX(field,flen,value,vlen)
#endif

typedef struct {
  char *rname;
  void (*cb)(char *field, size_t flen);
} http_req_t;



#endif /* !__MOD_HTTP_H__ */
