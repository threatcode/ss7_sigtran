/*
 * tlv-test.c
 */
#include <stdlib.h>
#include <string.h>
#include "mytlv.h"

int main(int argc, char **argv)
{
  uint16_t tag, len;
  uint32_t val;
  octet data[32];
  uint16_t nextpos;
  tlv_t *t;
  octet *buf;
  uint16_t i;

  i = nextpos = 0;

  tag = 0x0200; len = 4; val = 0x00; t = mytlv_build(tag, &val, len); buf = mytlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;
  tag = 0x0006; len = 4; val = 0x01; t = mytlv_build(tag, &val, len); buf = mytlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;
  tag = 0x0210; len = 4; val = 0x02; t = mytlv_build(tag, &val, len); buf = mytlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;
  tag = 0x0013; len = 4; val = 0x03; t = mytlv_build(tag, &val, len); buf = mytlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;

  i = nextpos = 0;
  for (i = 0; i < sizeof(data); i += nextpos) {
    t = octet2mytlv(data+i, sizeof(data)-i, &nextpos); mytlv_dump(t); free(t);
  }

  return 0;
}

