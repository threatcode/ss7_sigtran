/*
 * http11_requests.h
 */
#ifndef _HTTP11_REQUESTS_H_
#define _HTTP11_REQUESTS_H_

#include <stdio.h>
#include <string.h>

#include <stdint.h>
#include <unistd.h>

#if USE_MPH
#include "mph.h"

typedef mph_key_t hrq_key_t;
typedef mph_tab_t hrq_tab_t;

int hrq_init(void);
void hrq_free(void);

int hrq_key_id(const char *key, size_t klen);
hrq_key_t *hrq_key(unsigned int id);

#endif



#endif
