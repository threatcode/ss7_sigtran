/*
 * url-utils.h
 */
#ifndef _URL_UTILS_H_
#define _URL_UTILS_H_

#include <curl/curl.h>
#include "llist.h"

typedef CURL url_t;

void url_system_init(void);
url_t *url_handle_new(void);
void url_handle_free(url_t *url_handle);
char *url_get_contents(url_t *url_handle, const char *url, size_t *size);
char *url_post_contents(url_t *url_handle, const char *url, llist_t *list, size_t *size);
char *url_encode(url_t *url_handle, const char *value, size_t *size);
//char *url_decode(url_t *url_handle, const char *u, int *size);
void url_system_cleanup(void);

#define url_encode_free(x) curl_free(x)

#endif
