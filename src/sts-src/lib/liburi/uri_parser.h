/*
 * uri_parser.h
 */
#ifndef __URI_PARSER_H__
#define __URI_PARSER_H__

/* TODO:
 * Normalization and Comparison
 * http://tools.ietf.org/html/rfc3986#section-6
 */

struct uri_s {
  /*
   * char *chunk; // holds chunks of memory allocated, can be freed at one call
   */
  char *scheme;
  char *userinfo;
  char *host;
  char *path;
  char *query;
  char *fragment;
  unsigned short port;
};

typedef struct uri_s uri_t;

extern uri_t *uri_new(void);
extern int uri_parse(uri_t *u, const char *buf, size_t len, const char **error_at);
extern void uri_clear(uri_t *u);
extern void uri_free(uri_t *u);
extern void uri_print(uri_t *u);

#endif
