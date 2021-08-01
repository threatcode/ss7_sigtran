/*
 * tcap.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "tcap.h"
#include "utils.h"

#include <Component.h>

tcap_begin_msg_t *tcap_build_begin(uint8_t mtype, uint8_t mlen, tcap_tid_t *src)
{
  tcap_begin_msg_t *t = calloc(1, sizeof(tcap_begin_msg_t));
  t->mtype = mtype;
  t->mlen = mlen;
  memcpy(&t->src_tid, src, sizeof(tcap_tid_t));

  return t;
}

tcap_continue_msg_t *tcap_build_continue(uint8_t mtype, uint8_t mlen, tcap_tid_t *src)
{
  tcap_continue_msg_t *t = calloc(1, sizeof(tcap_continue_msg_t));
  t->mtype = mtype;
  t->mlen = mlen;
  memcpy(&t->src_tid, src, sizeof(tcap_tid_t));

  return t;
}

tcap_end_msg_t *tcap_build_end(uint8_t mtype, uint8_t mlen, tcap_tid_t *dst)
{
  tcap_end_msg_t *t = calloc(1, sizeof(tcap_end_msg_t));
  t->mtype = mtype;
  t->mlen = mlen;
  memcpy(&t->dst_tid, dst, sizeof(tcap_tid_t));

  return t;
}

tcap_abort_msg_t *tcap_build_abort(uint8_t mtype, uint8_t mlen, tcap_tid_t *dst)
{
  tcap_abort_msg_t *t = calloc(1, sizeof(tcap_abort_msg_t));
  t->mtype = mtype;
  t->mlen = mlen;
  memcpy(&t->dst_tid, dst, sizeof(tcap_tid_t));

  return t;
}

/* pack tcap_begin to byte-stream */
octet *tcap_begin2octet(tcap_begin_msg_t *t, uint16_t *nextpos)
{
  uint16_t len = 0;
  octet *ret = NULL;

  *nextpos = 0;

#if 0
  int i;
  if (!t || !t->mlen || t->mlen < 8) return NULL;

  len = t->mlen;
  octet *ret = calloc(1, len+rem);

  i = 0;
  tlv->tag = htons(tlv->tag);
  memcpy((ret+i), &tlv->tag, 2);
  i += 2;
  tlv->len = htons(tlv->len);
  memcpy((ret+i), &tlv->len, 2);
  i += 2;
  memcpy((ret+i), tlv->val, len-4); /* len - tag_len - len_len */
#endif

  *nextpos = len;

  return ret;
}

/* nextpos helps us rescan the buffer for more TLVs */
tcap_begin_msg_t *octet2tcap_begin(octet *buf, uint16_t buflen, uint16_t *nextpos)
{
  tcap_begin_msg_t *t;
  int i;
  uint8_t break_loop = 0;

  *nextpos = 0;

  if (!buf || buflen < 4 || buflen > SIGTRAN_MTU) return NULL;

  t = calloc(1, sizeof(tcap_begin_msg_t));

  i = 0;

  t->mtype = buf[i++];
  t->mlen = buf[i++];

  while (i < buflen && !break_loop) {
    switch (buf[i]) {
      case TCAP_TID_SRC:
	t->src_tid.tag = buf[i++];
	t->src_tid.len = buf[i++];
	memcpy(&t->src_tid.tid, buf+i, t->src_tid.len);
	i += t->src_tid.len;
	break;
      case TCAP_DIALOG_PORTION_TAG:
	/* optional dialog portion exists */
	t->dlg_part = calloc(1, sizeof(tcap_dlg_part_t));
	t->dlg_part->tag = buf[i++];
	t->dlg_part->len = buf[i++];
	memcpy(t->dlg_part->dlg_info, buf+i, t->dlg_part->len);
	i += t->dlg_part->len;
	break;
      case TCAP_COMPONENT_PORTION_TAG:
	/* optional components portion exists */
	t->cmp_part = calloc(1, sizeof(tcap_cmp_part_t));
	t->cmp_part->tag = buf[i++];
	t->cmp_part->len = buf[i++];
	memcpy(t->cmp_part->cmp_info, buf+i, t->cmp_part->len);
	i += t->cmp_part->len;

	/* go deep inside */
	//tcap_begin_cmp_part_parse(&t->cmp_part);
	break;
      default:
	break_loop = 1;
	break;
    }
  }

  *nextpos = i;

  return t;
}


/* parse t->cmp_info to find out component type */
tcap_cmp_type_t *tcap_cmp_part_parse(tcap_cmp_part_t *t)
{
  uint8_t i;
  tcap_cmp_type_t *ct = calloc(1, sizeof(tcap_cmp_type_t));
  i = 0;
  ct->type = t->cmp_info[i++];
  ct->len = t->cmp_info[i++];

  /* parse tlvs */
  tlv_t *tlv;

  while (i < t->len) {
    tlv = calloc(1, sizeof(tlv_t));
    tlv->tag = t->cmp_info[i++];
    tlv->len = t->cmp_info[i++];
    memcpy(tlv->val, t->cmp_info+i, tlv->len);
    ct->tlvs = llist_add(ct->tlvs, tlv);
    i += tlv->len;
  }

  return ct;

}

/* CONSTRUCTOR: bit 6 is 1 */
/* I found that usually it is 0x30 */
uint8_t tcap_tag_is_constructor(uint8_t tag)
{
  return ((tag << 2) >> 7);
}

void tcap_cmp_type_dump(tcap_cmp_type_t *ct)
{
  uint32_t val;

  if (!ct) return;

  fprintf(stderr, "Component Type Tag: 0x%02x (%u)\n", ct->type, ct->type);
  fprintf(stderr, "Component Length: 0x%02x (%u)\n", ct->len, ct->len);

  tlv_t *tlv;
  llist_t *tmp = ct->tlvs;

  tlv = (tlv_t *) tmp->data;

  fprintf(stderr, "Invoke ID Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
  fprintf(stderr, "Invoke ID Length: 0x%02x (%u)\n", tlv->len, tlv->len);
  if (tlv->len == 1) {
    val = tlv->val[0];
  } else {
    memcpy(&val, tlv->val, tlv->len);
  }
  fprintf(stderr, "Invoke ID: 0x%02x (%u)\n", val, val);

  tmp = tmp->next;


  switch (ct->type) {
    case TCAP_CMP_TYPE_INVOKE:
      fprintf(stderr, "Invoke Component\n");

      while (tmp) {
	tlv = (tlv_t *) tmp->data;

	switch (tlv->tag) {
	  case TCAP_CMP_ID_LINKED:
	    /* don't know what this is or how it can be useful right now */
	    break;
	  case TCAP_CMP_OPCODE_TAG_LOCAL:
	    fprintf(stderr, "Local Operation Code Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Local Operation Code Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Local Operation Code Value: 0x%02x (%u)\n", val, val);
	    break;
	  case TCAP_CMP_OPCODE_TAG_GLOBAL:
	    fprintf(stderr, "Global Operation Code Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Global Operation Code Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Global Operation Code Value: 0x%02x (%u)\n", val, val);
	    break;
	  default:
	    break;
	}

	if (tcap_tag_is_constructor(tlv->tag)) {
	  fprintf(stderr, "Constructor Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	  fprintf(stderr, "Constructor Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	}

	tmp = tmp->next;
      }

      break;
    case TCAP_CMP_TYPE_RETURN_RESULT:
    case TCAP_CMP_TYPE_RETURN_RESULT_LAST:
      fprintf(stderr, "ReturnResult (Last/Not Last) Component\n");

      while (tmp) {
	tlv = (tlv_t *) tmp->data;

	switch (tlv->tag) {
	  case TCAP_CMP_ID_LINKED:
	    /* don't know what this is or how it can be useful right now */
	    break;
	  case TCAP_CMP_OPCODE_TAG_LOCAL:
	    fprintf(stderr, "Local Operation Code Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Local Operation Code Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Local Operation Code Value: 0x%02x (%u)\n", val, val);
	    break;
	  case TCAP_CMP_OPCODE_TAG_GLOBAL:
	    fprintf(stderr, "Global Operation Code Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Global Operation Code Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Global Operation Code Value: 0x%02x (%u)\n", val, val);
	    break;
	  default:
	    break;
	}

	if (tcap_tag_is_constructor(tlv->tag)) {
	  fprintf(stderr, "Constructor Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	  fprintf(stderr, "Constructor Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	}

	tmp = tmp->next;
      }

      break;
    case TCAP_CMP_TYPE_RETURN_ERROR:
      fprintf(stderr, "ReturnError Component\n");

      while (tmp) {
	tlv = (tlv_t *) tmp->data;

	switch (tlv->tag) {
	  case TCAP_CMP_TAG_ERROR_LOCAL:
	    fprintf(stderr, "Local Error Code Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Local Error Code Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Local Error Code Value: 0x%02x (%u)\n", val, val);
	    break;
	  case TCAP_CMP_TAG_ERROR_GLOBAL:
	    fprintf(stderr, "Global Error Code Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Global Error Code Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Global Error Code Value: 0x%02x (%u)\n", val, val);
	    break;
	  default:
	    break;
	}

	if (tcap_tag_is_constructor(tlv->tag)) {
	  fprintf(stderr, "Constructor Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	  fprintf(stderr, "Constructor Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	}

	tmp = tmp->next;
      }

      break;

    case TCAP_CMP_TYPE_REJECT:
      fprintf(stderr, "Reject Component\n");

      while (tmp) {
	tlv = (tlv_t *) tmp->data;

	switch (tlv->tag) {
	  case TCAP_CMP_PROBLEM_GENERAL:
	    fprintf(stderr, "General Problem: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Tag Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Value: 0x%02x (%u)\n", val, val);
	    break;
	  case TCAP_CMP_PROBLEM_INVOKE:
	    fprintf(stderr, "Invoke Problem: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Tag Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Value: 0x%02x (%u)\n", val, val);
	    break;
	  case TCAP_CMP_PROBLEM_RETURN_RESULT:
	    fprintf(stderr, "Return Result Problem: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Tag Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Value: 0x%02x (%u)\n", val, val);
	    break;
	  case TCAP_CMP_PROBLEM_RETURN_ERROR:
	    fprintf(stderr, "Return Error Problem: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	    fprintf(stderr, "Tag Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	    if (tlv->len == 1) {
	      val = tlv->val[0];
	    } else {
	      memcpy(&val, tlv->val, tlv->len);
	    }
	    fprintf(stderr, "Value: 0x%02x (%u)\n", val, val);
	    break;
	  default:
	    break;
	}

	if (tcap_tag_is_constructor(tlv->tag)) {
	  fprintf(stderr, "Constructor Tag: 0x%02x (%u)\n", tlv->tag, tlv->tag);
	  fprintf(stderr, "Constructor Length: 0x%02x (%u)\n", tlv->len, tlv->len);
	}

	tmp = tmp->next;
      }
      break;

    default:
      fprintf(stderr, "Unknown Component\n");
      break;
  }

}

void tcap_cmp_type_free(tcap_cmp_type_t *ct)
{
  if (ct) {
    llist_free(ct->tlvs);
    free(ct);
  }
}


/* nextpos helps us rescan the buffer for more TLVs */
tcap_continue_msg_t *octet2tcap_continue(octet *buf, uint16_t buflen, uint16_t *nextpos)
{
  tcap_continue_msg_t *t;
  int i;

  *nextpos = 0;

  if (!buf || buflen < 4 || buflen > SIGTRAN_MTU) return NULL;

  t = calloc(1, sizeof(tcap_continue_msg_t));

  i = 0;

  t->mtype = buf[i++];
  t->mlen = buf[i++];
  if (buf[i] == TCAP_TID_SRC) {
    t->src_tid.tag = buf[i++];
    t->src_tid.len = buf[i++];
    memcpy(&t->src_tid.tid, buf+i, t->src_tid.len);
    i += t->src_tid.len;
  }

  *nextpos = i;

  return t;
}

/* nextpos helps us rescan the buffer for more TLVs */
tcap_end_msg_t *octet2tcap_end(octet *buf, uint16_t buflen, uint16_t *nextpos)
{
  tcap_end_msg_t *t;
  int i;

  *nextpos = 0;

  if (!buf || buflen < 4 || buflen > SIGTRAN_MTU) return NULL;

  t = calloc(1, sizeof(tcap_end_msg_t));

  i = 0;

  t->mtype = buf[i++];
  t->mlen = buf[i++];
  if (buf[i] == TCAP_TID_SRC) {
    t->dst_tid.tag = buf[i++];
    t->dst_tid.len = buf[i++];
    memcpy(&t->dst_tid.tid, buf+i, t->dst_tid.len);
    i += t->dst_tid.len;
  }

  *nextpos = i;

  return t;
}

/* nextpos helps us rescan the buffer for more TLVs */
tcap_abort_msg_t *octet2tcap_abort(octet *buf, uint16_t buflen, uint16_t *nextpos)
{
  tcap_abort_msg_t *t;
  int i;

  *nextpos = 0;

  if (!buf || buflen < 4 || buflen > SIGTRAN_MTU) return NULL;

  t = calloc(1, sizeof(tcap_abort_msg_t));

  i = 0;

  t->mtype = buf[i++];
  t->mlen = buf[i++];
  if (buf[i] == TCAP_TID_SRC) {
    t->dst_tid.tag = buf[i++];
    t->dst_tid.len = buf[i++];
    memcpy(&t->dst_tid.tid, buf+i, t->dst_tid.len);
    i += t->dst_tid.len;
  }

  *nextpos = i;

  return t;
}

void map_decode(const void *buf, size_t len)
{
  asn_dec_rval_t rval;
  Component_t *pdu = 0; /* Note this 0! (Forgetting to properly initialize the pointing to a destination structure is a major source of support requests) */

  rval = ber_decode(0,
      &asn_DEF_Component,
      (void **) &pdu, /* Decoder moves the pointer */
      buf, len);

  if (rval.code == RC_OK) {
    fprintf(stderr, "Decoded successfully\n");
     xer_fprint(stdout, &asn_DEF_Component, pdu);
  } else {
    /* Free partially decoded data */
    fprintf(stderr, "Decode failed, Freeing partially parased data structure\n");
  }
  asn_DEF_Component.free_struct(&asn_DEF_Component, pdu, 0);
}

void tcap_dump_begin(tcap_begin_msg_t *t)
{
  if (!t) return;

  fprintf(stderr, "Message Type: 0x%02x (%u)\n", t->mtype, t->mtype);
  fprintf(stderr, "Message Length: 0x%02x (%u)\n", t->mlen, t->mlen);
  fprintf(stderr, "Source Transaction ID (len): 0x%02x (%u)\n", t->src_tid.len, t->src_tid.len);
  hexdump(t->src_tid.tid, t->src_tid.len); /* -4 because len includes the tag-len fields */

  if (t->dlg_part) {
    fprintf(stderr, "Dialogue Portion Tag: 0x%02x (%u)\n", t->dlg_part->tag, t->dlg_part->tag);
    fprintf(stderr, "Dialogue Portion Length: 0x%02x (%u)\n", t->dlg_part->len, t->dlg_part->len);
    hexdump(t->dlg_part->dlg_info, t->dlg_part->len); /* -4 because len includes the tag-len fields */
  }

  if (t->cmp_part) {
    fprintf(stderr, "Component Portion Tag: 0x%02x (%u)\n", t->cmp_part->tag, t->cmp_part->tag);
    fprintf(stderr, "Component Portion Length: 0x%02x (%u)\n", t->cmp_part->len, t->cmp_part->len);
    hexdump(t->cmp_part->cmp_info, t->cmp_part->len); /* -4 because len includes the tag-len fields */
    map_decode(t->cmp_part->cmp_info, t->cmp_part->len);
  }
}

void tcap_dump_continue(tcap_continue_msg_t *t)
{
  if (!t) return;

  fprintf(stderr, "Message Type: 0x%02x (%u)\n", t->mtype, t->mtype);
  fprintf(stderr, "Message Length: 0x%02x (%u)\n", t->mlen, t->mlen);
  fprintf(stderr, "Source Transaction ID (len): 0x%02x (%u)\n", t->src_tid.len, t->src_tid.len);
  hexdump(t->src_tid.tid, t->src_tid.len); /* -4 because len includes the tag-len fields */
  fprintf(stderr, "Destination Transaction ID (len): 0x%02x (%u)\n", t->dst_tid.len, t->dst_tid.len);
  hexdump(t->dst_tid.tid, t->dst_tid.len); /* -4 because len includes the tag-len fields */
}

void tcap_dump_end(tcap_end_msg_t *t)
{
  if (!t) return;

  fprintf(stderr, "Message Type: 0x%02x (%u)\n", t->mtype, t->mtype);
  fprintf(stderr, "Message Length: 0x%02x (%u)\n", t->mlen, t->mlen);
  fprintf(stderr, "Destination Transaction ID (len): 0x%02x (%u)\n", t->dst_tid.len, t->dst_tid.len);
  hexdump(t->dst_tid.tid, t->dst_tid.len); /* -4 because len includes the tag-len fields */
}

void tcap_dump_abort(tcap_abort_msg_t *t)
{
  if (!t) return;

  fprintf(stderr, "Message Type: 0x%02x (%u)\n", t->mtype, t->mtype);
  fprintf(stderr, "Message Length: 0x%02x (%u)\n", t->mlen, t->mlen);
  fprintf(stderr, "Destination Transaction ID (len): 0x%02x (%u)\n", t->dst_tid.len, t->dst_tid.len);
  hexdump(t->dst_tid.tid, t->dst_tid.len); /* -4 because len includes the tag-len fields */
}


void tcap_free_begin(tcap_begin_msg_t *t)
{
  if (!t) return;

  if (t->dlg_part) tcap_dlg_part_free(t->dlg_part);
  if (t->cmp_part) tcap_cmp_part_free(t->cmp_part);
  free(t);
}

void tcap_dlg_part_free(tcap_dlg_part_t *d)
{
  if (!d) return;

  free(d);
}

void tcap_cmp_part_free(tcap_cmp_part_t *c)
{
  if (!c) return;

  free(c);
}
