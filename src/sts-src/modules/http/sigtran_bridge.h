/*
 * sigtran_bridge.h
 */
#ifndef _SIGTRAN_BRIDGE_H_
#define _SIGTRAN_BRIDGE_H_

#include <sys/types.h>
#include <inttypes.h>

extern size_t sigtran_http_resp_func(void *sys, const char *request_path, const char *query_string, char *resp_body, size_t resp_body_len);

#endif
