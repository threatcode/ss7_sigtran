/*
 * uri-utils.h
 */
#ifndef _URL_UTILS_H_
#define _URL_UTILS_H_

//#include "llist.h"

//typedef CURL url_t;

//void uri_system_init(void);
//uri_contents_t *uri_contents_new(uri_t *u);
//void uri_handle_free(uri_t *uri_handle);
char *uri_get_contents(const char *uri, int urilen, size_t *size);
//char *url_post_contents(url_t *url_handle, const char *url, llist_t *list, size_t *size);
//char *url_encode(url_t *url_handle, const char *value, size_t *size);
//char *url_decode(url_t *url_handle, const char *u, int *size);
//void url_system_cleanup(void);

//#define url_encode_free(x) curl_free(x)

#endif
