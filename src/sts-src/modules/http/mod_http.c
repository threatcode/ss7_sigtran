/*
 * mod_http.c
 * http module
 */
#include "mod_http.h"

static void http_fragment_cb(void *data, const char *at, size_t len)
{
  FTRACE();
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif
  return;
}

static void http_request_uri_cb(void *data, const char *at, size_t len)
{
  FTRACE();
  /*
   * will be called when request uri is parsed
   */
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif
  return;
}

static void http_request_method_cb(void *data, const char *at, size_t len)
{
  FTRACE();
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif
  if (HTTP_VERIFY_METHOD(at, len) == ERROR) { DTRACE("Error in method\n"); }
}

static void http_request_path_cb(void *data, const char *at, size_t len)
{
  FTRACE();

  /*
   * will be called when request path is parsed
   */
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif

  http_session_data_t *sd = data;
  if (sd) {
    if (len >= sizeof(sd->request_path)) len = sizeof(sd->request_path)-1;
    memcpy(sd->request_path, at, len);
    sd->request_path[len] = '\0';
    sd->request_path_len = len;
  }
}


static void http_field_cb(void *data,
    const char *field, size_t flen,
    const char *value, size_t vlen)
{
  FTRACE();
  /*
  http_session_data_t *sd = data;

  if (hrq_key_id(field, flen) < 0) {
    write(STDERR_FILENO, field, flen);
    write(STDERR_FILENO, "\n", 1);
  }
  */
  /*
   * header fields in key (field), value (value)
   */
#ifdef DUMP_HTTP
  DUMPX(field,flen,value,vlen);
#endif
}

static void http_query_string_cb(void *data, const char *at, size_t len)
{
  FTRACE();

  /*
   * will be called if any query string passed
   */
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif

  http_session_data_t *sd = data;
  if (sd) {
    if (len >= sizeof(sd->query_string)) len = sizeof(sd->query_string)-1;
    memcpy(sd->query_string, at, len);
    sd->query_string[len] = '\0'; /* NUL terminate the buffer */
    sd->query_string_len = len;
  }

}

static void http_version_cb(void *data, const char *at, size_t len)
{
  FTRACE();
  /*
   * will be called if any query string passed
   */
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif

  http_session_data_t *sd = data;
  if (sd) {
    if (len >= sizeof(sd->http_version)) len = sizeof(sd->http_version)-1;
    memcpy(sd->http_version, at, len);
    sd->http_version[len] = '\0'; /* NUL terminate the buffer */
    sd->http_version_len = len;
  }

}


static void http_header_done_cb(void *data, const char *at, size_t len)
{
  FTRACE();
  /*
   * will be called if parsing header is done
   */
#ifdef DUMP_HTTP
  DUMP(at,len);
#endif
}

static int http_parse_header(http_session_data_t *sd, size_t off)
{
  FTRACE();
  int retval = -1;
  http_parser parser;
  http_parser_init(&parser);

  parser.http_field = http_field_cb;
  parser.request_method = http_request_method_cb;
  parser.request_uri = http_request_uri_cb;
  parser.fragment = http_fragment_cb;
  parser.request_path = http_request_path_cb;
  parser.query_string = http_query_string_cb;
  parser.http_version = http_version_cb;
  parser.header_done = http_header_done_cb;


#if 0
  DTRACE("session_data_ptr=%p\n", sd);
  DEBUG(stderr, "===== HEADER START =====\n");
  write(2, header, len);
  write(2, "\n", 1);
  DEBUG(stderr, "=====  HEADER END  =====\n");
#endif

  parser.data = (void *) sd;
  char *header = sd->iov[0].iov_base;
  size_t len = sd->iov0_pos;
  retval = http_parser_execute(&parser, header, len, off);
  if (!http_parser_is_finished(&parser) || http_parser_has_error(&parser)) {
    DTRACE("HTTP Header not complete or with error!\n");
    retval = -1;
  }

#if 0
  else {
    fprintf(stderr, "Header parse finished\n");
  }
  fprintf(stderr, "retval=%d\n", retval);
#endif

  return retval;
}

static void *http_process_data(void *s, void *sys)
{
  FTRACE();
  ssize_t n = 0;
#ifndef MAXBUFSIZ
#define MAXBUFSIZ 4096
#endif
  char buf[MAXBUFSIZ];
  char hbuf[HTTP_MAXHEADER]; /* header buffer */
  size_t hlen = 0; /* header length */
  size_t blen = 0; /* body length */
  ssize_t nwritten;
  char *ptr;
  ssize_t err = 0;
  size_t tlen; /* temporary length calculation */
  http_session_t *hs = (http_session_t *) s;
  http_session_data_t *sd = (http_session_data_t *) hs->data;
  if (!sd) {
    DTRACE("Session Data NULL. Skipped processing.!!!\n");
    err = -1;
    goto yield;
  }

  while ((n = recv(hs->fd, buf, sizeof(buf)-1, 0)) > 0) {
#if 0
    fprintf(stderr, "Received data\n");
#endif
    if (sd->iov0_pos + n > HTTP_MAXHEADER) {
      DTRACE("Exceeded maximum header size %d. Suspicious. Ignoring.\n", HTTP_MAXHEADER);
      err = -1;
      goto yield;
    }
    /*
    if ((sd->iov0_pos + n) >= sd->iov[0].iov_len) {
      fprintf(stderr, "Expanding space in iov[0], newsize = %d\n", (int) (sd->iov0_pos+n+1));
      ptr = MYREALLOC(sd->iov[0].iov_base, sd->iov0_pos + n + 1);
      if (ptr) {
	sd->iov[0].iov_base = ptr;
	sd->iov[0].iov_len = sd->iov0_pos + n + 1;
      } else {
	err = -1;
	goto yield;
      }
    }
    */

    memcpy((sd->iov[0].iov_base)+(sd->iov0_pos), buf, n);
    sd->iov0_pos += n;

#if 0
    temp += n;
    fprintf(stderr, "Going to read more data.\n");
#endif
    /* consume data */
  }

  *(char *) ((char *) sd->iov[0].iov_base+sd->iov0_pos) = '\0';
#if 0
  write(2, sd->iov[0].iov_base, sd->iov0_pos);
  write(2, "\n", 1);
#endif
  if (strstr(sd->iov[0].iov_base, "\r\n\r\n") ||
      strstr(sd->iov[0].iov_base, "\n\n") ||
      strstr(sd->iov[0].iov_base, "\r\r")) {
#if 0
    fprintf(stderr, "strlen iov[0] = %d, pos = %d\n", strlen(sd->iov[0].iov_base), sd->iov0_pos);
    fprintf(stderr, "header dump:\n%s\n", (char *) sd->iov[0].iov_base);
    err = http_parse_header(sd, sd->iov[0].iov_base, sd->iov0_pos, 0);
#endif
    err = http_parse_header(sd, 0);
    if (err < 0) {
      fprintf(stderr, "[%s:%d]: Error parsing header.\n", __FILE__, __LINE__);
      err = 0;
      goto yield;
    }
  } else {
    /*
    fprintf(stderr, "More data needed to proceed.\n");
    */
    err = 2;
    goto yield;
  }

  if (err < 0) goto yield;
#if 0
  buf[sizeof(buf)-1] = '\0';
  parse_header(buf, temp, 0);
#endif

  /* fprintf(stdout, "Header OK\n"); */
  /* now generate response */

  if (!sd->resp_func) {
    err = -1;
    goto yield;
  }

  memset(buf, 0, sizeof(buf));
  blen = sd->resp_func(sys, sd->request_path, sd->query_string, buf, sizeof(buf));
  if (blen == 0) {
    err = -1; /* for now we are strictly going to close session if any zero or negative ouptput from function occurs (should be more flexible later) */
    goto yield;
  }

  /* fill up header */
  memset(hbuf, 0, sizeof(hbuf));
  /*
   * The  functions  snprintf()  and  vsnprintf()  do not write more than size bytes (including the trailing '\0').  If the output was truncated due to this limit then the
   * return value is the number of characters (not including the trailing '\0') which would have been written to the final string  if  enough  space  had  been  available.
   * Thus, a return value of size or more means that the output was truncated.
   */
  hlen = snprintf(hbuf, sizeof(hbuf)-1, HTTP_RESP_HDR_FMT, sd->http_version, blen); /* we're always leaving the NUL byte, for safety */
  if (hlen >= (sizeof(hbuf)-1)) hlen = sizeof(hbuf)-1;

  if (sd->iov0_len < hlen) {
    DTRACE("Expanding space in iov[0], newsize = %ld\n", hlen);
    ptr = MYREALLOC(sd->iov[0].iov_base, hlen);
    if (ptr) {
      sd->iov[0].iov_base = ptr;
      sd->iov0_len = sd->iov[0].iov_len = hlen; /* iov0_len is updated only for new allocations */
    } else {
      err = -1;
      goto yield;
    }
  }

  if (sd->iov1_len < blen) {
    DTRACE("Expanding space in iov[1], newsize = %ld\n", blen);
    ptr = MYREALLOC(sd->iov[1].iov_base, blen);
    if (ptr) {
      sd->iov[1].iov_base = ptr;
      sd->iov1_len = sd->iov[1].iov_len = blen; /* iov1_len is updated only for new allocations */
    } else {
      err = -1;
      goto yield;
    }
  }

  /* copy header */
  memcpy(sd->iov[0].iov_base, hbuf, hlen); /* copy the header */
  sd->iov0_pos = sd->iov[0].iov_len = hlen; /* update the positions */

  memcpy(sd->iov[1].iov_base, buf, blen);
  sd->iov1_pos = sd->iov[1].iov_len = blen;

  tlen = sd->iov[0].iov_len + sd->iov[1].iov_len;
  nwritten = writev(hs->fd, sd->iov, 2);
  if (nwritten < tlen) {
    fprintf(stderr, "Less data written!\n");
    err = -1;
    goto yield;
  }

  err = 0; /* wait for more requests (keep-alive) from this client */

yield:
  switch (err) {
    case 0:
      /* reset position markers */
      sd->iov0_pos = 0;
      sd->iov1_pos = 0;
      break;
    case -1:
      http_session_close(hs, (system_t *) sys);
      break;
    default:
      err = 0;
      break;
  }

  return NULL;
}


static void *http_on_data(void *self, void *sys)
{
  FTRACE();

  void *ret = NULL;
  http_session_t *s = self;
  if (CHECKFLAG(s->ev.events, EPOLLRDHUP) ||
      CHECKFLAG(s->ev.events, EPOLLHUP) ||
      CHECKFLAG(s->ev.events, EPOLLERR)
     ) {
    DTRACE("Client socket got EPOLL{RDHUP|HUP|ERR}. Closing session.\n");
    http_session_close(s,(system_t *) sys);
    ret = NULL;
  } else {
    /*
    int x = s->fd % NWORKERS;
    */
    http_session_data_t *sd = s->data;
    if (!sd) {
      sd = http_session_data_new();
      /* currently hardcoded, later it will be assigned on the fly (after parsing http request) */
      sd->resp_func = sigtran_http_resp_func; /* defined in sigtran module (will be resolved runtime) */
      DTRACE("HTTP Session Data allocated\n");
    }
    if (sd && !sd->initialized) {
      sd->iov[0].iov_base = MYCALLOC(1, HTTP_MAXHEADER);
      sd->iov[0].iov_len = HTTP_MAXHEADER;
      sd->iov[1].iov_base = MYCALLOC(1, 512); /* will be expanded as needed */
      sd->iov[1].iov_len = 512;
      sd->initialized = 1;

      sd->iov0_len = sd->iov[0].iov_len;
      sd->iov1_len = sd->iov[1].iov_len;
    }
    s->data = sd;
    ret = s;
  }

  return ret;
}


static void *http_on_connect(void *self, void *sys)
{
  FTRACE();

  int connfd;
  int value = 1;
  struct sockaddr_in local;
  socklen_t addrlen = sizeof(local);
  hook_t *h = (hook_t *) self;
  http_session_t *s;
  while ((connfd = ACCEPT(h->fd, (struct sockaddr *) &local, &addrlen)) > 0) {
    http_session_new(s, (system_t *) sys, connfd);
    if (s) {
      setsockopt(connfd, IPPROTO_IP, TCP_NODELAY, &value, sizeof(value));
      s->fd = connfd;
      *(&s->ready) = http_on_data;
      *(&s->process) = http_process_data;
      s->ev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLET;
      s->ev.data.ptr = s;
      EVQ_ADD(((system_t *) sys)->eventfd, s->fd, &s->ev);
    } else {
      close(connfd);
    }
  }

  return NULL;
}

int module_start(system_t *sys)
{
  FTRACE();

  struct sockaddr_in addr = { 0 };
  int sockfd = 0;
  int type = 0;

  int one = 1;

#ifdef __linux__
  type =SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
#else
  type = SOCK_STREAM;
#endif
  
  sockfd = socket(AF_INET, /* family */
      type, /* type */
      0); /* protocol */
  if (sockfd == -1) {
    perror("socket");
    goto err;
  }

  one = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

#ifdef USELINGER
  struct linger ling = { 1, 1 };
  setsockopt(sys->aws.sockfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)); /* graceful */
#endif

#ifdef NODELAY
  one = 1;
  setsockopt(sys->aws.sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(HTTP_PORT);
  if (inet_pton(AF_INET, HTTP_ADDR, &addr.sin_addr) != 1) {
    DTRACE("Error getting IPv4 address from %s. Will try to use wildcard address.\n", HTTP_ADDR);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    perror("bind");
    goto err;
  }

#ifndef BACKLOG
  /* check /proc/sys/net/core/somaxconn */
#define BACKLOG 1000
#endif
  if (listen(sockfd, BACKLOG) == -1) { /* 128: backlog */
    perror("listen");
    goto err;
  }

  hook_t *s = hook_new();
  if (s) {
    s->fd = sockfd;
    s->ready = http_on_connect;
    s->ev.events = EPOLLIN;
    s->ev.data.ptr = s;
  } else {
    goto err;
  }


  /*
   * load other modules
   */
#ifdef USE_MPH
  hrq_init();
#endif


  EVQ_ADD(sys->eventfd, sockfd, &s->ev);

  return sockfd;

err:
  DTRACE("*** Error Initializing HTTP Subsystem.***\n");

  if (sockfd > 0) close(sockfd);
  return -1;
}

int module_stop(system_t *sys, module_t *mod)
{
  FTRACE();

  if (mod && mod->fd > 0) close(mod->fd);
  /*
   * closing the descriptor automatically removes it from the event
  EVQ_DEL(sys->eventfd, mod->fd);
  */
  return 0;
}


