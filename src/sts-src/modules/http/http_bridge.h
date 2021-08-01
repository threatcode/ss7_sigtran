/*
 * http_bridge.h
 */
#ifndef _HTTP_BRIDGE_H_
#define _HTTP_BRIDGE_H_

typedef int (*bridge_func)(const char *request_path, const char *args, void *user_data);

typedef struct {
  char request_path[256]; /* /module */
  bridge_func request_func;
  void *user_data; /* user defined pointer, will be passed as last parameter */
  uint8_t func_may_block; /* whether a separate thread should be created in case the function call may block */
} http_bridge_reg_t;



#endif
