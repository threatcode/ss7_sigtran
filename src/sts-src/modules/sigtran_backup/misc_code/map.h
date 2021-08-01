/*
 * map.h
 */
#ifndef _MAP_H_
#define _MAP_H_

#include "Invoke.h"
#include <constr_TYPE.h>

typedef struct {
  char *buf;
  size_t buf_size;
  size_t used;
} out_t;



MAP_DialoguePDU_t *map_decode(const void *buf, size_t len);
void tcap_encode(TCMessage_t *tcm, out_t *out);
void *inap_decode(Invoke_t *invoke, asn_TYPE_descriptor_t **type);
int tcap_extract_from_buf(const char *buf, size_t len, const char *spec, out_t *out);
int tcap_extract_from_struct(TCMessage_t *tcm, const char *spec, out_t *out);
int inap_extract_from_buf(const char *buf, size_t len, const char *spec, out_t *out);
int inap_extract(TCMessage_t *tcm, size_t len, const char *spec, out_t *out);

#define OUTPUT_BUFFER_INIT(o,i) output_buffer_init(o, i, sizeof(i))
static inline void output_buffer_init(out_t *o, char *i, size_t s)
{
  o->buf = i;
  o->buf_size = s;
  o->used = 0;
}


#endif
