/*
 * mytlv.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "mytlv.h"
#include "utils.h"

/* tlv utility functions */
/* len is the length of the val */
tlv_t *mytlv_build(uint16_t tag, void *val, uint16_t len)
{
  tlv_t *t = calloc(1, sizeof(tlv_t));
  t->tag = tag;
  t->len = 4+len;
  memcpy(t->val, val, len);

  return t;
}

/* pack tlv to byte-stream */
octet *mytlv2octet(tlv_t *tlv, uint16_t *nextpos)
{
  int i;
  uint16_t len, rem;

  *nextpos = 0;

  if (!tlv || !tlv->len || tlv->len < 4) return NULL;

  len = tlv->len;
  rem = len % 4;
  octet *ret = calloc(1, len+rem);

  i = 0;
  tlv->tag = htons(tlv->tag);
  memcpy((ret+i), &tlv->tag, 2);
  i += 2;
  tlv->len = htons(tlv->len);
  memcpy((ret+i), &tlv->len, 2);
  i += 2;
  memcpy((ret+i), tlv->val, len-4); /* len - tag_len - len_len */

  *nextpos = len+rem;

  return ret;
}

/* nextpos helps us rescan the buffer for more TLVs */
tlv_t *octet2mytlv(octet *buf, uint16_t buflen, uint16_t *nextpos)
{
  tlv_t *t;
  int i;
  uint16_t rem;

  *nextpos = 0;

  if (!buf || buflen < 4 || buflen > SIGTRAN_MTU) return NULL;

  t = calloc(1, sizeof(tlv_t));

  i = 0;
  memcpy(&t->tag, buf+i, 2);
  t->tag = ntohs(t->tag);
  i += 2;
  memcpy(&t->len, buf+i, 2);
  t->len = ntohs(t->len);
  if (t->len > buflen) { /* buffer must be equal or longer than tlv->len */
    free(t);
    return NULL;
  }

  i += 2;
  memcpy(t->val, buf+i, t->len-4);
  i += t->len - 4;
  //fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);

  *nextpos = i;
  rem = t->len % 4;
  *nextpos += rem;

  return t;
}

void mytlv_dump(tlv_t *tlv)
{
  if (!tlv) return;

  fprintf(stdout, "Tag: 0x%04x (%hu)\n", tlv->tag, tlv->tag);
  fprintf(stdout, "Len: 0x%04x (%hu)\n", tlv->len, tlv->len);
  hexdump(tlv->val, tlv->len-4); /* -4 because len includes the tag-len fields */
}

