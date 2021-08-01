/*
 * m3ua-test.c
 */
#include <stdlib.h>
#include <string.h>
#include "m3ua.h"

int main(int argc, char **argv)
{
  uint8_t mc, mt;
  octet data[32];
  uint32_t nextpos;
  m3ua_t *m;
  octet *buf;
  uint32_t i;
  uint32_t datalen;

  i = nextpos = 0;

  mc = M3UA_MSG_CLASS_ASPSM; mt = M3UA_MSG_TYPE_ASPSM_ASPUP; m = m3ua_build(mc, mt, NULL); buf = m3ua2octet(m, &nextpos); memcpy(data+i, buf, nextpos); free(m); free(buf); i += nextpos;
  mc = M3UA_MSG_CLASS_ASPTM; mt = M3UA_MSG_TYPE_ASPTM_ASPAC; m = m3ua_build(mc, mt, NULL); buf = m3ua2octet(m, &nextpos); memcpy(data+i, buf, nextpos); free(m); free(buf); i += nextpos;
#if 0
  tag = 0x0006; len = 4; val = 0x01; t = tlv_build(tag, &val, len); buf = tlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;
  tag = 0x0210; len = 4; val = 0x02; t = tlv_build(tag, &val, len); buf = tlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;
  tag = 0x0013; len = 4; val = 0x03; t = tlv_build(tag, &val, len); buf = tlv2octet(t, &nextpos); memcpy(data+i, buf, nextpos); free(t); free(buf); i += nextpos;
#endif
  datalen = i;

  i = nextpos = 0;
  for (i = 0; i < datalen; i += nextpos) {
    m = octet2m3ua(data+i, sizeof(data)-i, &nextpos); m3ua_dump(m); free(m);
  }

  return 0;
}

