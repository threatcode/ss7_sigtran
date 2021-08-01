#include <stdio.h>
#include "uri_parser.h"
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include "mymdebug.h"


#include <stdio.h>

#define URI_DEFINE_SETTER(field) \
  static void uri_set_##field(uri_t *u, const char *s, ssize_t l) { \
    if (!u) return; \
    if (s == 0) { u->field = 0; return; } \
    if (l == -1) { l = strlen(s); } \
    u->field = MYMALLOC(l+1); \
    if (!u->field) return; \
    memcpy(u->field, s, l); \
    *(u->field+l) = '\0'; \
  }

URI_DEFINE_SETTER(scheme)
URI_DEFINE_SETTER(userinfo)
URI_DEFINE_SETTER(host)
URI_DEFINE_SETTER(path)
URI_DEFINE_SETTER(query)
URI_DEFINE_SETTER(fragment)

%%{
  machine uri_parser;

  action mark {
    mark = fpc;
  }

  action scheme {
    uri_set_scheme(u, mark, fpc-mark);
  }

  action userinfo {
    uri_set_userinfo(u, mark, fpc-mark);
  }

  action host {
    /* host may be called multiple times because
     * the parser isn't able to figure out the difference
     * between the userinfo and host until after the @ is encountered
     * FIXME: in that case there may be memory leak.
     * FIXME: for that something like GStringChunk can be developed
     */
    uri_set_host(u, mark, fpc-mark);
  }

  action port {
    if (mark) u->port = strtol(mark, NULL, 0);
  }

  action path {
    uri_set_path(u, mark, fpc-mark);
  }

  action query {
    uri_set_query(u, mark, fpc-mark);
  }

  action fragment {
    uri_set_fragment(u, mark, fpc-mark);
  }

  include uri_grammar "uri_grammar.rl";

  main := URI;
}%%

%% write data;

static void uri_zero(uri_t *u) {
/* zero everything */
  MYFREE(u->scheme); u->scheme = NULL;
  MYFREE(u->userinfo); u->userinfo = NULL;
  MYFREE(u->host); u->host = NULL;
  MYFREE(u->path); u->path = NULL;
  MYFREE(u->query); u->query = NULL;
  MYFREE(u->fragment); u->fragment = NULL;
  u->port = 80;
}

uri_t *uri_new(void) {
  uri_t *u = MYCALLOC(1, sizeof(uri_t));
  u->port = 80;
  return u;
}

int uri_parse(uri_t *u, const char *buf, size_t len, const char **error_at) {
  if (!u) return 0;
  const char *mark = NULL;
  const char *p, *pe, *eof;
  int cs = 0;

  if (error_at != NULL) {
    *error_at = NULL;
  }

  %% write init;

  p = buf;
  pe = buf+len;
  eof = pe;

  %% write exec;

  if (cs == uri_parser_error && error_at != NULL) {
    *error_at = p;
  }

  return (cs != uri_parser_error && cs >= uri_parser_first_final);
}

void uri_print(uri_t *u) {
  if (!u) return;
  fprintf(stderr,
    "scheme=%s,userinfo=%s,host=%s,path=%s,query=%s,fragment=%s,port=%hu\n",
    u->scheme, u->userinfo, u->host, u->path, u->query, u->fragment, u->port
  );
}

void uri_clear(uri_t *u) {
  if (u == NULL) return;
  uri_zero(u);
}

void uri_free(uri_t *u) {
  if (!u) return;
  MYFREE(u->scheme);
  MYFREE(u->userinfo);
  MYFREE(u->host);
  MYFREE(u->path);
  MYFREE(u->query);
  MYFREE(u->fragment);
  MYFREE(u);
}

