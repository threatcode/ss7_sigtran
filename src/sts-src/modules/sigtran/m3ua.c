/*
 * m3ua.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "m3ua.h"
#include "mytlv.h"

/* m3ua utility functions */
m3ua_t *m3ua_build(uint8_t mclass, uint8_t mtype, llist_t *tlvs)
{
  FTRACE();
  m3ua_t *m = MYCALLOC(1, sizeof(m3ua_t));

  m->head.version = 1;
  m->head.reserved = 0;
  m->head.mclass = mclass;
  m->head.mtype = mtype;
  m->head.mlen = 8; /* minimal size of the m3ua packet (just header) */
  if (tlvs) {
    m->tlvs = tlvs;
    llist_t *tmp = tlvs;
    mytlv_t *tlv = NULL;
    while (tmp) {
      tlv = tmp->data;
      m->head.mlen += tlv->len;
      tmp = tmp->next;
    }
  }

  m->head.mlen += m->head.mlen % 4; /* consider having padding bytes */

  return m;
}

/* pack m3ua to byte-stream */
octet *m3ua2octet(m3ua_t *m, uint32_t *nextpos)
{
  FTRACE();
  uint32_t i = 0;
  uint32_t len = 0;
  llist_t *tmp = NULL;
  uint16_t pos = 0;
  mytlv_t *tlv  = NULL;
  octet *buf = NULL;
  uint32_t pad = 0;
  octet *ret = NULL;

  if (nextpos) *nextpos = 0;
  pos = 0;

  if (!m) return NULL;

  pad = 0;
  len = m->head.mlen;
  if (len % 4 != 0) {
    pad = 4 - len % 4;
  }
  len += pad;
  //fprintf(stdout, "*** len=%u, mlen=%u, pad=%u\n", len, m->head.mlen, pad);

//  len = sizeof(m3ua_head_t);
//  tmp = m->tlvs;
//  while (tmp) {
//    tlv = tmp->data;
//    len += tlv->len + (tlv->len % 4); /* each TLV must be 4-byte aligned */
//    tmp = tmp->next;
//  }

  ret = MYCALLOC(1, len);
  if (nextpos) *nextpos = len;

//  m->head.mlen = len;

  i = 0;

  ret[i++] = m->head.version;
  /*
  memcpy((ret+i), &m->head.version, 1);
  i += 1;
  */
  ret[i++] = m->head.reserved;
  /*
  memcpy((ret+i), &m->head.reserved, 1);
  i += 1;
  */
  ret[i++] = m->head.mclass;
  /*
  memcpy((ret+i), &m->head.mclass, 1);
  i += 1;
  */
  ret[i++] = m->head.mtype;
  /*
  memcpy((ret+i), &m->head.mtype, 1);
  i += 1;
  */
  len = htonl(len);
  memcpy((ret+i), &len, 4);
  i += 4;

  /* now process the tlvs */
  tmp = m->tlvs;
  while (tmp) {
    tlv = tmp->data;

    buf = mytlv2octet(tlv, &pos);
    if (buf) {
      memcpy((ret+i), buf, pos);
      i += pos;
      MYFREE(buf);
    }

    tmp = tmp->next;
  }

//  *nextpos = i;

  return ret;
}

/* nextpos helps us rescan the buffer for more TLV/PDUs */
m3ua_t *octet2m3ua(octet *buf, uint16_t buflen, uint32_t *nextpos)
{
  FTRACE();
  m3ua_t *m = NULL;
  uint32_t i = 0;
  mytlv_t *t = NULL;
  uint16_t pos = 0;

  if (nextpos) *nextpos = 0;

  if (!buf || !buflen || buflen < 8 || buflen > SIGTRAN_MTU) return NULL;

  m = MYCALLOC(1, sizeof(m3ua_t));

  i = 0;

  m->head.version = buf[i++];
  /*
  memcpy(&m->head.version, buf+i, 1);
  i += 1;
  */

  m->head.reserved = buf[i++];
  /*
  memcpy(&m->head.reserved, buf+i, 1);
  i += 1;
  */

  m->head.mclass = buf[i++];
  /*
  memcpy(&m->head.mclass, buf+i, 1);
  i += 1;
  */

  m->head.mtype = buf[i++];
  /*
  memcpy(&m->head.mtype, buf+i, 1);
  i += 1;
  */

  memcpy(&m->head.mlen, buf+i, 4);
  m->head.mlen = ntohl(m->head.mlen);
  i += 4;

  if (m->head.mlen > 8) {
    while ((t = octet2mytlv(buf+i, buflen-i, &pos))) {
#if 0
      fprintf(stdout, "%s:%d\n", __FILE__, __LINE__);
      mytlv_dump(t);
#endif
      m3ua_add_tlv(m, t);
      i += pos;
      if (i >= buflen) break; /* don't go beyond the buffer */
    }
  }

  /* mlen includes padding bytes, so we shouldn't re-read them. so nextpos is considering the whole m3ua is read */
  if (nextpos) *nextpos = m->head.mlen;

  return m;
}

void m3ua_add_tlv(m3ua_t *m, mytlv_t *t)
{
  FTRACE();
  if (!m || !t) return;

  m->tlvs = llist_add(m->tlvs, t);
  m->head.mlen += t->len;
}

void m3ua_free(m3ua_t *m)
{
  FTRACE();
  if (!m) return;
  if (m->tlvs) llist_free(m->tlvs, MYFREE);
  MYFREE(m);
}

void m3ua_dump(m3ua_t *m)
{
  FTRACE();
  llist_t *tmp = NULL;
  mytlv_t *t = NULL;

  if (!m) return;

  fprintf(stdout, "Version: 0x%02x (%u)\n", m->head.version, m->head.version);
  fprintf(stdout, "Reserved: 0x%02x (%u)\n", m->head.reserved, m->head.reserved);
  fprintf(stdout, "Message Class: 0x%02x (%u) [%s]\n", m->head.mclass, m->head.mclass, m3ua_print_mclass(m));
  fprintf(stdout, "Message Type: 0x%02x (%u) [%s]\n", m->head.mtype, m->head.mtype, m3ua_print_mtype(m));
  fprintf(stdout, "Message Length: 0x%02x (%u)\n", m->head.mlen, m->head.mlen);

  /* dump tlvs */
  if (m->tlvs) {
    fprintf(stdout, "Dumping TLVs\n");

    tmp = m->tlvs;
    while (tmp) {
      t = (mytlv_t *) tmp->data;
      mytlv_dump(t);
      tmp = tmp->next;
    }
  }
}

const char *m3ua_print_mclass(m3ua_t *m)
{
  FTRACE();
  static const char *ret = NULL;
  static const char *mcstr[] = {
    "Management Message (MGMT)",
    "Transfer Message (TM)",
    "SS7 Signalling Network Management (SSNM)",
    "ASP State Maintenance (ASPSM)",
    "ASP Traffic Maintenance (ASPTM)",
    "Reserved for other Sigtran Adaptation Layers",
    "Reserved for other Sigtran Adaptation Layers",
    "Reserved for other Sigtran Adaptation Layers",
    "Reserved for other Sigtran Adaptation Layers",
    "Routing Key Management (RKM)"
  };
  static const char *mcstr_undef = "Reserved/Undefined";

  if ((sizeof(mcstr)/sizeof(mcstr[0])) > m->head.mclass)
    ret = mcstr[m->head.mclass];
  else
    ret = mcstr_undef;

  return ret;
}



const char *m3ua_print_mtype(m3ua_t *m)
{
  FTRACE();
  static const char *ret = NULL;
  static const char *mtstr_mgmt[] = { "Error (ERR)", "Notify (NTFY)" };
  static const char *mtstr_tm[] = { "Reserved", "Payload Data (DATA)" };
  static const char *mtstr_ssnm[] = { "Reserved", "Destination Unavailable (DUNA)",
    "Destination Available (DAVA)", "Destination State Audit (DAUD)",
    "Signalling Congestion (SCON)",
    "Destination User Part Unavailable (DUPU)",
    "Destination Restricted (DRST)" };
  static const char *mtstr_aspsm[] = {
    "Reserved", "ASP Up (ASPUP)", "ASP Down (ASPDN)", "Heartbeat (BEAT)",
    "ASP Up Acknowledgement (ASPUP_ACK)", "ASP Down Acknowledgement (ASPDN_ACK)",
    "Heartbeat Acknowledgement (BEAT_ACK)"
  };
  static const char *mtstr_asptm[] = {
    "Reserved", "ASP Active (ASPAC)", "ASP Inactive (ASPIA)", "ASP Active Acknowledgement (ASPAC_ACK)",
    "ASP Inactive Acknowledgement (ASPIA_ACK)"
  };
  static const char *mtstr_rkm[] = {
    "Reserved", "Registration Request (REG_REQ)",
    "Registration Response (REG_RSP)",
    "Deregistration Request (DEREG_REQ)",
    "Deregistration Response (DEREG_RSP)"
  };
  static const char *mtstr_undef = "Reserved/Undefined";

  switch (m->head.mclass) {
    case M3UA_MSG_CLASS_MGMT:
      if ((sizeof(mtstr_mgmt)/sizeof(mtstr_mgmt[0])) > m->head.mtype) ret = mtstr_mgmt[m->head.mtype];
      else ret = mtstr_undef;
      break;
    case M3UA_MSG_CLASS_TM:
      if ((sizeof(mtstr_tm)/sizeof(mtstr_tm[0])) > m->head.mtype) ret = mtstr_tm[m->head.mtype];
      else ret = mtstr_undef;
      break;
    case M3UA_MSG_CLASS_SSNM:
      if ((sizeof(mtstr_ssnm)/sizeof(mtstr_ssnm[0])) > m->head.mtype) ret = mtstr_ssnm[m->head.mtype];
      else ret = mtstr_undef;
      break;
    case M3UA_MSG_CLASS_ASPSM:
      if ((sizeof(mtstr_aspsm)/sizeof(mtstr_aspsm[0])) > m->head.mtype) ret = mtstr_aspsm[m->head.mtype];
      else ret = mtstr_undef;
      break;
    case M3UA_MSG_CLASS_ASPTM:
      if ((sizeof(mtstr_asptm)/sizeof(mtstr_asptm[0])) > m->head.mtype) ret = mtstr_asptm[m->head.mtype];
      else ret = mtstr_undef;
      break;
    case M3UA_MSG_CLASS_RKM:
      if ((sizeof(mtstr_rkm)/sizeof(mtstr_rkm[0])) > m->head.mtype) ret = mtstr_rkm[m->head.mtype];
      else ret = mtstr_undef;
      break;
    default:
      ret = mtstr_undef;
      break;
  }

  return ret;
}



/* m3ua wrapper functions for ease of development */
octet *m3ua_octet_ASPUP(uint32_t *nextpos)
{
  FTRACE();
  uint8_t mc = 0, mt = 0;
  m3ua_t *m = NULL;
  octet *buf = NULL;

  if (nextpos) *nextpos = 0;

  mc = M3UA_MSG_CLASS_ASPSM;
  mt = M3UA_MSG_TYPE_ASPSM_ASPUP;
  m = m3ua_build(mc, mt, NULL);
  buf = m3ua2octet(m, nextpos);
  m3ua_free(m);

  return buf;
}

octet *m3ua_octet_ASPDN(uint32_t *nextpos)
{
  FTRACE();
  uint8_t mc = 0, mt = 0;
  m3ua_t *m = NULL;
  octet *buf = NULL;

  if (nextpos) *nextpos = 0;

  mc = M3UA_MSG_CLASS_ASPSM;
  mt = M3UA_MSG_TYPE_ASPSM_ASPDN;
  m = m3ua_build(mc, mt, NULL);
  buf = m3ua2octet(m, nextpos);
  m3ua_free(m);

  return buf;
}

octet *m3ua_octet_ASPAC(uint32_t *nextpos)
{
  FTRACE();
  uint8_t mc = 0, mt = 0;
  m3ua_t *m = NULL;
  octet *buf = NULL;

  if (nextpos) *nextpos = 0;

  mc = M3UA_MSG_CLASS_ASPTM;
  mt = M3UA_MSG_TYPE_ASPTM_ASPAC;
  m = m3ua_build(mc, mt, NULL);
  buf = m3ua2octet(m, nextpos);
  m3ua_free(m);

  return buf;
}

octet *m3ua_octet_ASPIA(uint32_t *nextpos)
{
  FTRACE();
  uint8_t mc = 0, mt = 0;
  m3ua_t *m = NULL;
  octet *buf = NULL;

  *nextpos = 0;

  mc = M3UA_MSG_CLASS_ASPTM;
  mt = M3UA_MSG_TYPE_ASPTM_ASPIA;
  m = m3ua_build(mc, mt, NULL);
  buf = m3ua2octet(m, nextpos);
  m3ua_free(m);

  return buf;
}

octet *m3ua_octet_DAVA(uint32_t pc, uint32_t *nextpos)
{
  FTRACE();
  uint8_t mc = 0, mt = 0;
  m3ua_t *m = NULL;
  octet *buf = NULL;
  mytlv_t *t = NULL;

  if (nextpos) *nextpos = 0;

  mc = M3UA_MSG_CLASS_SSNM;
  mt = M3UA_MSG_TYPE_SSNM_DAVA;
  m = m3ua_build(mc, mt, NULL);
  pc = htonl(pc); /* must have to be in network byte order */
  t = mytlv_build(0x0012, &pc, 4);
  m3ua_add_tlv(m, t);

  buf = m3ua2octet(m, nextpos);
  m3ua_free(m);

  return buf;
}

octet *m3ua_octet_ASPSM_BEAT(uint32_t m3ua_hb, uint32_t *nextpos)
{
  FTRACE();
  uint8_t mc = 0, mt = 0;
  m3ua_t *m = NULL;
  octet *buf = NULL;
  mytlv_t *t = NULL;

  if (nextpos) *nextpos = 0;

  mc = M3UA_MSG_CLASS_ASPSM;
  mt = M3UA_MSG_TYPE_ASPSM_BEAT;
  m = m3ua_build(mc, mt, NULL);
  t = mytlv_build(0x0009, &m3ua_hb, sizeof(m3ua_hb));
  m3ua_add_tlv(m, t);

  buf = m3ua2octet(m, nextpos);
  m3ua_free(m);

  return buf;
}


m3ua_protocol_data_t *m3ua_octet2pdata(octet *buf, uint16_t buflen, uint32_t *nextpos)
{
  FTRACE();

  uint32_t i = 0;
  if (nextpos) *nextpos = 0;
  m3ua_protocol_data_t *pdata = MYCALLOC(1, sizeof(*pdata));

  memcpy(&pdata->opc, buf+i, 4);
  pdata->opc = ntohl(pdata->opc); /* convert to host byte order */
  i += 4;

  memcpy(&pdata->dpc, buf+i, 4);
  pdata->dpc = ntohl(pdata->dpc); /* convert to host byte order */
  i += 4;

  pdata->si = buf[i++];
  pdata->ni = buf[i++];
  pdata->mp = buf[i++];
  pdata->sls = buf[i++];
  //pdata->sls = 0x00;
  /* i = 12 here */
  pdata->datalen = buflen-i;
  memcpy(pdata->data, buf+i, pdata->datalen);
  i += pdata->datalen;

  if (nextpos) *nextpos = i;

  return pdata;

}

octet *m3ua_pdata2octet(m3ua_protocol_data_t *pdata, uint32_t *nextpos)
{
  FTRACE();
  uint16_t i = 0;
  uint16_t buflen = 0;

  if (nextpos) *nextpos = 0;
  if (!pdata) return NULL;

  buflen = 4+4+4+pdata->datalen;
  octet *buf = MYCALLOC(1, buflen);

  pdata->opc = htonl(pdata->opc);
  memcpy(buf+i, &pdata->opc, 4);
  i += 4;

  pdata->dpc = htonl(pdata->dpc);
  memcpy(buf+i, &pdata->dpc, 4);
  i += 4;


  buf[i++] = pdata->si;
  buf[i++] = pdata->ni;
  buf[i++] = pdata->mp;
  buf[i++] = pdata->sls;

  /* i = 12 here */
  memcpy(buf+i, pdata->data, pdata->datalen);
  i += pdata->datalen;

  *nextpos = i;

  return buf;
}

void m3ua_pdata_dump(m3ua_protocol_data_t *pdata)
{
  FTRACE();
  if (pdata) {
    fprintf(stdout, "OPC: 0x%x (%u)\n", pdata->opc, pdata->opc);
    fprintf(stdout, "DPC: 0x%x (%u)\n", pdata->dpc, pdata->dpc);
    fprintf(stdout, "SI: 0x%x (%u)\n", pdata->si, pdata->si);
    fprintf(stdout, "NI: 0x%x (%u)\n", pdata->ni, pdata->ni);
    fprintf(stdout, "MP: 0x%x (%u)\n", pdata->mp, pdata->mp);
    fprintf(stdout, "SLS: 0x%x (%u)\n", pdata->sls, pdata->sls);
    fprintf(stdout, "User Data Length: 0x%x (%u)\n", pdata->datalen, pdata->datalen);
  }
}

