/*
 * sigtran_tcap.c
 */
#include "defs.h"
#include "sigtran_tcap.h"
#include "mod_sigtran.h"
#include "map-dialog-mgmt.h"
#include "map-utils.h"


#include "tcap.h"

#include <time.h>
#include "utils.h"

//#include "gsm.h"

#include "dialogue-utils.h"
#include "uri-utils.h"
#include "sigtran_tcap.h"

#include "CellGlobalIdOrServiceAreaIdOrLAI.h"


void sigtran_tcap_begin(sigtran_t *s, octet *data, uint16_t data_len);
void sigtran_tcap_continue(sigtran_t *s, octet *data, uint16_t data_len);
void sigtran_tcap_end(sigtran_t *s, octet *data, uint16_t data_len);
void sigtran_tcap_abort(sigtran_t *s, octet *data, uint16_t data_len);
static map_t *map_init(sigtran_t *s);
void *map_stack_start(void *index);
void *ussd_session_handler(void *data);
void *ati_session_handler(void *data);
int sigtran_tcap_resolve_map_id(sigtran_tcap_info_t *sinfo, uint16_t *map_id, uint16_t *dialogue_id);


typedef struct {
  void *data;
  void (*free_func)(void *);
} parsed_data_t;


void tcap_session_dump(tcap_session_t *info);

typedef struct {
  map_t *map;
  uint16_t map_id;
} map_worker_t;

/* msisdn parameter will be passed in case of MT USSD */
int tcap_msg_resp(sigtran_tcap_info_t *sinfo, const char *msg, const char *msisdn, int flow)
{
  FTRACE();
  int ret = -1;

  int notify_only = 0;
  ComponentPortion_t *cp = NULL;
  ExternalPDU_t *ext = NULL;
  Component_t *comp = NULL;
//  DialoguePDU_t *dial = NULL;
  TCMessage_t *tcm = NULL;
  asn_enc_rval_t er = { 0 };  /* Encoder return value */

  tcap_session_t *tcsess = sinfo->tcsess;
  OCTET_STRING_t *o1 = NULL, *o2 = NULL; /* to free later */

//  DTRACE("msg=%s, msisdn=%s, flow=%d\n", msg, msisdn, flow);

  tcm = MYCALLOC(1, sizeof(*tcm));

  if ((tcsess->momt == MOMT_MT) && (flow == TCMessage_PR_end)) { /* handle MT session */
    notify_only = 1;
    flow = TCMessage_PR_continue; /* MT sessions are 'ended/aborted' by MS/Network always when user receives it */
  }

  tcm->present = flow;
  switch (flow) {
    case TCMessage_PR_begin: /* For USSD MT Dialogue */
      TTRACE("<<< tcap: begin (otid=%x)\n", tcsess->ugw_tid);
      OCTET_STRING_fromBuf(&tcm->choice.begin.otid,
	  (const char *) &tcsess->ugw_tid, sizeof(tcsess->ugw_tid));
      o1 = &tcm->choice.begin.otid;
      break;
    case TCMessage_PR_continue:
      TTRACE("<<< tcap: continue (otid=%x, dtid=%x)\n", tcsess->ugw_tid, tcsess->hlr_tid);
      OCTET_STRING_fromBuf(&tcm->choice.Continue.dtid,
	  (const char *) &tcsess->hlr_tid, sizeof(tcsess->hlr_tid));
      o1 = &tcm->choice.Continue.dtid;
      OCTET_STRING_fromBuf(&tcm->choice.Continue.otid,
	  (const char *) &tcsess->ugw_tid, sizeof(tcsess->ugw_tid));
      o2 = &tcm->choice.Continue.otid;
      break;
    default:
      TTRACE("<<< tcap: end (dtid=%x)\n", tcsess->hlr_tid);
      OCTET_STRING_fromBuf(&tcm->choice.end.dtid,
	  (const char *) &tcsess->hlr_tid, sizeof(tcsess->hlr_tid));
      o2 = &tcm->choice.end.dtid;
      break;
  }

  //xer_fprint(stdout, &asn_DEF_DialoguePDU, dial);
  if (tcsess->dialog_pdu_needed) {
    DTRACE("Dialogue PDU needed\n");
    if (flow == TCMessage_PR_begin) { /* MT USSD */
      ext = ussd_dialogue_request_build(msisdn, sinfo->st->hlr_gt);
      tcm->choice.begin.dialoguePortion = ext;
    } else { /* continue/end/abort/whatever error */
      ext = ussd_dialogue_response_accepted();
      if (flow == TCMessage_PR_continue) {
	tcm->choice.Continue.dialoguePortion = ext;
      } else if (flow == TCMessage_PR_end) {
	tcm->choice.end.dialoguePortion = ext;
      }
    }
    tcsess->dialog_pdu_needed = 0; /* dialogue pdu not needed anymore after this first one */
  } else {
    DTRACE("Not including dialogue response\n");
  }
  //ussd_notify_aare(&ext->dialog);

  //int dpdu_size = ANY_fromType((ANY_t *) &ext->dialog, &asn_DEF_DialoguePDU, dial);


  /* add SEQUENCE_OF invoke component */
  cp = MYCALLOC(1, sizeof(*cp));
  if (flow == TCMessage_PR_begin) { /* begin */
    tcm->choice.begin.components = cp;
  } else if (flow == TCMessage_PR_continue) { /* continue */
    tcm->choice.Continue.components = cp;
  } else { /* end */
    tcm->choice.end.components = cp;
  }
  comp = ussd_session_comp_build(tcsess, msg, NULL, flow, notify_only); /* MSISDN not required in response */
  ASN_SEQUENCE_ADD(&cp->list, comp);
  cp->list.free = ussd_session_comp_free;
  //asn_sequence_add(&cp->list, comp);
  //xer_fprint(stdout, &asn_DEF_TCMessage, tcm);

  er = der_encode_to_buffer(&asn_DEF_TCMessage, tcm, sinfo->udt->data, sizeof(sinfo->udt->data));
  if (er.encoded > 0) {
    sinfo->udt->data_len = er.encoded;
    ret = 1;
    //DTRACE("Encoded successfully, %ld bytes\n", er.encoded);
    //sccp_dump_udt(sinfo->udt);
    //hexdump(sinfo->udt->data, sinfo->udt->data_len);
  } else {
    ret = -1;
    DTRACE("Failed to encode TCAP Data\n");
  }

  asn_set_empty(&cp->list); /* this will call the free function set (ussd_session_comp_free) */
  MYFREE(cp);
  //ussd_session_comp_free(comp);
  /* free allocations */
  //if (cp) MYFREE(cp);

  if (flow == TCMessage_PR_begin) {
    ussd_dialogue_request_free(ext);
  } else {
    ussd_dialogue_response_free(ext);
  }

  if (o1) ASN_FREE_DATA(asn_DEF_OCTET_STRING, o1);
  if (o2) ASN_FREE_DATA(asn_DEF_OCTET_STRING, o2);

  if (tcm) MYFREE(tcm);

  return ret;
}

/* Parameter_t is of type ANY_t which is {buf, size} */
int sigtran_tcap_parameter_parse(sigtran_tcap_info_t *sinfo)
{
  FTRACE();

  int ret = -1;
  uint8_t gsm_bits = 7;
  int septets = 0;
  uint8_t len = 0;
  pthread_t tid;
  int is_ati = 0;

#if 0
  pthread_attr_t attr;
#endif

  USSD_Arg_t *uinfo = NULL;
  AnyTimeInterrogationRes_t *ainfo = NULL;
  ussd_session_t *usessinfo = NULL;
  tcap_session_t *tcsess = NULL;
  Parameter_t *param = NULL;

  uint8_t octets_written = 0;
  LocationInformation_t *linfo = NULL;
  CellGlobalIdOrServiceAreaIdOrLAI_t *cgi = NULL;
  OCTET_STRING_t *cgip = NULL;



  if (!sinfo) goto end;


  tcsess = sinfo->tcsess;
  if (!tcsess) goto end;

  usessinfo = MYCALLOC(1, sizeof(ussd_session_t));
  sinfo->usessinfo = usessinfo;
  usessinfo->tcsess = tcsess;
  usessinfo->map_stack_id = tid2map_id(tcsess->ugw_tid);
  usessinfo->dialogue_id = tid2dialogue_id(tcsess->ugw_tid);




  switch (tcsess->opcode) {
    case GSMMAPOperationLocalvalue_processUnstructuredSS_Request:
      DTRACE("opcode: processUnstructuredSS_Request [%ld]\n", tcsess->opcode);
      TTRACE(">>> map opcode: processUnstructuredSS_Request [%ld]\n", tcsess->opcode);
      break;
    case GSMMAPOperationLocalvalue_unstructuredSS_Request:
      DTRACE("opcode: unstructuredSS_Request [%ld]\n", tcsess->opcode);
      TTRACE(">>> map opcode: ustructuredSS_Request [%ld]\n", tcsess->opcode);
      break;
    case GSMMAPOperationLocalvalue_anyTimeInterrogation:
      is_ati = 1;
      DTRACE("opcode: anyTimeInterrogation [%ld]\n", tcsess->opcode);
      TTRACE(">>> map opcode: anyTimeInterrogation [%ld]\n", tcsess->opcode);
      break;
    case GSMMAPOperationLocalvalue_sendRoutingInfo: /* SRI (NOT IMPLEMENTED YET)  */
      DTRACE("opcode: sendRoutingInfo [%ld]\n", tcsess->opcode);
      TTRACE(">>> map opcode: sendRoutingInfo [%ld]\n", tcsess->opcode);
      break;
    default:
      DTRACE("opcode: UNKNOWN [%ld]\n", tcsess->opcode);
      TTRACE(">>> map opcode: [%ld]\n", tcsess->opcode);
      if (tcsess->aborted) {
	DTRACE("Aborted session. Imitate parsing.\n");
      } else {
	goto end;
      }
  }


  if (tcsess->aborted) {
    strcpy(usessinfo->msisdn, tcsess->msisdn); /* copy back when no msisdn information in MAP packet, for completeness) */
    usessinfo->msisdn_len = tcsess->msisdn_len;
    usessinfo->ussd_string[0] = '\0';
    usessinfo->ussd_string_len = 0;
    usessinfo->is_ati = is_ati;

    if (is_ati) {
      param = sinfo->param;
      if (!param) {
	goto noparam;
      }

      ainfo = ati_decode(param->buf, param->size);
      if (!ainfo) {
	goto noparam;
      }
      //ati_print(ainfo);
      linfo = ainfo->subscriberInfo.locationInformation;
      if (linfo) {
	if (linfo->ageOfLocationInformation) {
	  usessinfo->age_of_location = *ainfo->subscriberInfo.locationInformation->ageOfLocationInformation;
	  //fprintf(stderr, "***** AGE: %ld *****\n", usessinfo->age_of_location);
	}
	octets_written = sizeof(usessinfo->vlr_no);
	if (linfo->vlr_number) {
	  decode_msisdn(linfo->vlr_number->buf, linfo->vlr_number->size, usessinfo->vlr_no, &octets_written);
	  //fprintf(stderr, "***** VLR: %s *****\n", usessinfo->vlr_no);
	}
	if (linfo->cellGlobalIdOrServiceAreaIdOrLAI) {
	  cgi = linfo->cellGlobalIdOrServiceAreaIdOrLAI;

	  uint8_t m[4] = { 0 };
	  uint8_t tm = 0;
	  switch (cgi->present) {
	    case CellGlobalIdOrServiceAreaIdOrLAI_PR_cellGlobalIdOrServiceAreaIdFixedLength:
	      //hexdump(cgi->choice.cellGlobalIdOrServiceAreaIdFixedLength.buf, cgi->choice.cellGlobalIdOrServiceAreaIdFixedLength.size);
	      cgip = &cgi->choice.cellGlobalIdOrServiceAreaIdFixedLength;
	      memset(m, 0, sizeof(m));
	      tm = *(cgip->buf+0);
	      m[0] = tm & 0x0f;
	      m[1] = tm >> 4;
	      tm = *(cgip->buf+1);
	      m[2] = tm & 0x0f;
	      /* now compute mcc */
	      usessinfo->mcc = m[0]*100+m[1]*10+m[2];

	      memset(m, 0, sizeof(m));
	      //tm = 0;

	      if (tm >> 4 != 0x0f) { /* 3 digit MNC */
		m[2] = tm >> 4;
	      } else {
		m[2] = 0xff;
	      }
	      tm = *(cgip->buf+2);
	      m[0] = tm & 0x0f;
	      m[1] = tm >> 4;
	      /* now compute mnc */
	      if (m[2] == 0xff) { /* 2 digit mnc */
		usessinfo->mnc = m[0]*10+m[1];
	      } else {
		usessinfo->mnc = m[0]*100+m[1]*10+m[2];
	      }

	      memcpy(&usessinfo->lac, cgip->buf+3, sizeof(usessinfo->lac));
	      memcpy(&usessinfo->ci, cgip->buf+5, sizeof(usessinfo->ci));
	      usessinfo->lac = ntohs(usessinfo->lac);
	      usessinfo->ci = ntohs(usessinfo->ci);
	      //fprintf(stderr, "***** (LAC,CELLID)=(%hu,%hu) *****\n", usessinfo->lac, usessinfo->cid);
	      usessinfo->ussd_string_len = sprintf(usessinfo->ussd_string, "age=%ld,vlr=%s,mcc=%u,mnc=%u,lac=%u,ci=%u",
		  usessinfo->age_of_location, usessinfo->vlr_no, usessinfo->mcc, usessinfo->mnc, usessinfo->lac, usessinfo->ci);
	      break;
	    default:
	      break;
	  }
	}
      }
    } else {
      usessinfo->ussd_string[0] = '\0';
      usessinfo->ussd_string_len = 0;
    }

    goto aborted;
  }


  param = sinfo->param;
  if (!param) goto noparam;

  uinfo = ussd_decode(param->buf, param->size);
  if (!uinfo) goto noparam;

  usessinfo->dcs = uinfo->ussd_DataCodingScheme.buf[0];
  //tcsess->dcs = uinfo->ussd_DataCodingScheme.buf[0];
  //xer_fprint(stdout, &asn_DEF_USSD_Arg, uinfo);

  /* more languages will be handled later */
  if (usessinfo->dcs >> 4 == 0x0) {
    gsm_bits = 7; /* Coding Group 0 (Language using the GSM 7 bit default alphabet (0)) */
  } else { /* consider binary, other options will be enabled in future */
    gsm_bits = 8;
  }

  if (gsm_bits == 7) {
    septets = uinfo->ussd_String.size * 8 / gsm_bits;
    len = gsm_7bit_decode_n_ussd(usessinfo->ussd_string, sizeof(usessinfo->ussd_string), uinfo->ussd_String.buf, septets);
    //len = utf8_from_gsm7(uinfo->ussd_String.buf, 0, uinfo->ussd_String.size, (bytes_t) usessinfo->ussd_string);
    usessinfo->ussd_string_len = len;
  } else {
    len = uinfo->ussd_String.size;
    memcpy(usessinfo->ussd_string, uinfo->ussd_String.buf, len);
    if (usessinfo->ussd_string[len-1] != '\0') usessinfo->ussd_string[len] = '\0'; /* nul terminate string */
    usessinfo->ussd_string_len = len;
  }
//  len = gsm_7bit_decode_n_ussd(usessinfo->ussd_string, sizeof(usessinfo->ussd_string), uinfo->ussd_String.buf, septets);
  //fprintf(stderr, "Decoded USSD String (%u): %s\n", len, sess->ussd_string);
  if (uinfo->msisdn) {
    //fprintf(stderr, "MSISDN of length %d found\n", uinfo->msisdn->size);
    decode_msisdn(uinfo->msisdn->buf, uinfo->msisdn->size, usessinfo->msisdn, &len);
    usessinfo->msisdn_len = len;
    strcpy(tcsess->msisdn, usessinfo->msisdn);
    tcsess->msisdn_len = usessinfo->msisdn_len;
    /* keep a copy to tcap session for future use (when there may be no msisdn in MAP packet) */
    //fprintf(stderr, "Decoded MSISDN (%u): %s\n", len, info->msisdn);
  } else {
    strcpy(usessinfo->msisdn, tcsess->msisdn); /* copy back when no msisdn information in MAP packet, for completeness) */
    usessinfo->msisdn_len = tcsess->msisdn_len;
  }
  TTRACE(">>> map param: msisdn=%s, text=%s\n", usessinfo->msisdn, usessinfo->ussd_string);
  ussd_free(uinfo);

noparam:
aborted:

#if 0
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif
  //ret = pthread_create(&tid, &attr, ussd_session_handler, sinfo);
  ret = pthread_create(&tid, NULL, ussd_session_handler, sinfo);
  pthread_detach(tid);
#if 0
  pthread_attr_destroy(&attr);
#endif
  //ussd_session_handler(sinfo);
  //tcap_session_dump(tcsess);

end:
  /*
     uint16_t map_id = sigtran_tcap_resolve_map_id(sinfo);
     fprintf(stderr, "Going to put to queue of MAP STACK [%u]\n", map_id);
     lfq_enqueue(sinfo->st->tcap.map->mq[map_id], mpacket);
     sem_post(&sinfo->st->tcap.map->sem[map_id]);
     */
  /* now we have all the information to send this to API for processing */
  return ret;
}

/* ussd session handler thread */
void *ussd_session_handler(void *data)
{
  FTRACE();
  int ret = -1;

  sigtran_tcap_info_t *sinfo = NULL;
  sigtran_t *s = NULL;
  ussd_session_t *usessinfo = NULL;
  tcap_session_t *tcsess = NULL;
  char *msg = NULL;
  int flow = 0;
  uint64_t one = 0UL;
  char q[2] = { 0 };
  size_t size = 0;
#define MAXURI 512
  char uribuf[MAXURI] = { 0 };
  int urilen = 0;
  char *escaped = NULL;
  //uri_t *url_handle = NULL;
  uint32_t *tid = NULL;
  ssize_t nw = 0;

  const char *err_resp = "0Service temporarily unavailable. Pleasae try later.";


  sinfo = data;
  if (!sinfo) goto end;
  usessinfo = sinfo->usessinfo;
  if  (!usessinfo) goto end;
  tcsess = sinfo->tcsess;
  if (!tcsess) goto end;
  s = sinfo->st;
  if (!s) goto end;

//  DTRACE("MAP Stack ID: %u, MAP Dialogue ID: %u\n", usessinfo->map_stack_id, usessinfo->dialogue_id);


  //ussd_session_dump(usessinfo);

//      uint8_t len = gsm_7bit_decode_n_ussd(usessinfo->ussd_string, sizeof(usessinfo->ussd_string), uinfo->ussd_String.buf, septets);

#define MAX_USSD_STRING 182
#ifndef UGWTEST
  q[1] = '\0';
  if (strchr(s->appurl, '?')) {
    q[0] = '\0'; /* nothing to add */
  } else {
    q[0] = '?'; /* add query string */
  }
  //url_handle = url_handle_new();
  //escaped = url_encode(url_handle, usessinfo->ussd_string, &size); /* we already have url handle, we can use it to encode */
  escaped = rawurlencode(usessinfo->ussd_string, usessinfo->ussd_string_len, &size); /* why use third party if you have a working version ? */
  if (escaped) {
    memset(uribuf, 0, sizeof(uribuf));
    urilen = snprintf(uribuf, sizeof(uribuf)-1,
       	"%s%s"
	"transactionID=%u&"
	"map_stack_id=%hu&"
	"dialogid=%hu&"
	"number=%s&"
	"text=%s&"
	"status=%s&"
	"momt=%s&"
	"error=%u&"
	"lbs=%u&"
	"opcode=%ld",
       	s->appurl, q,
	tcsess->ugw_tid,
	usessinfo->map_stack_id,
	usessinfo->dialogue_id,
	usessinfo->msisdn,
	escaped,
	tcsess->flow_desc,
	tcsess->momt_desc,
	tcsess->error,
	usessinfo->is_ati,
	tcsess->opcode);
    MYFREE(escaped);
    //url_encode_free(escaped);
#ifdef DEBUG
    fprintf(stderr, "URI {%u}: [%s]\n", tcsess->ugw_tid, uribuf);
#endif
    msg = uri_get_contents(uribuf, urilen, &size);
#ifdef DEBUG
    fprintf(stderr, "RESP {%u}: [%s]\n", tcsess->ugw_tid, msg);
#endif
    if (msg && size > (MAX_USSD_STRING+1)) { /* FIXME: MAX USSD STRING + Prefix byte (only for GSM7 alphabet, next version should be more robust) */
      *(msg+MAX_USSD_STRING+1) = '\0';
      size = MAX_USSD_STRING;
#ifdef DEBUG
      fprintf(stderr, "RESP {%u} [TRIM]: [%s]\n", tcsess->ugw_tid, msg);
#endif
    }
    //fprintf(stderr, "Length: %d\nData: [%s]\n", size, msg);
    //MYFREE(contents);
  }
  //url_handle_free(url_handle);
#else /* UGWTEST */
  msg = MYSTRDUP(err_resp);
  size = strlen(msg);
#endif

  if (tcsess->aborted) goto aborted;

//  const char *endmsg = "0Service under maintenance. Please try again later.";
//  const char *contmsg = "1Type something";
//  char *msisdn = NULL;

  if (!msg || size <= 1) {
    if (msg) MYFREE(msg); /* maybe local API replied but the upstream didn't */
    msg = MYSTRDUP(err_resp);
    size = strlen(msg);
  }
  //msg = endmsg;
  if (msg && msg[0] == '1') {
    flow = TCMessage_PR_continue;
  } else {
    flow = TCMessage_PR_end;
    if (tcsess->momt == MOMT_MO) tcsess->aborted = 1;
  }

  TTRACE("<<< map: msisdn=%s, text=%s\n", tcsess->msisdn, msg+1);
  ret = tcap_msg_resp(sinfo, msg+1, NULL, flow); /* msisdn is NULL because in reply we don't need it */
  if (ret <= 0) goto end;

  //sinfo->comp_resp = ussd_notify_invoke(sinfo);
  /*
   * done, now send back to sigtran module to write to wire
   */

  /* sinfo->udt->data is properly filled up by tcap */
  one = 1UL;
  pthread_mutex_lock(&s->tcap.mutex);
  lfq_enqueue(s->tcap.q_fr_tcap, sinfo);
  if (tcsess->aborted) {
    tid = MYCALLOC(1, sizeof(uint32_t));
    *tid = tcsess->ugw_tid;
    lfq_enqueue(s->tcap.dfq, tid); /* pointers are at least 32 bits long, information shouldn't be lost */
  }
  nw = write(s->tcap.efd, &one, sizeof(one)); /* wake up the sigtran part to send response back */
  if (nw != sizeof(one)) DTRACE("Attempted to write %lu bytes, but wrote %ld bytes\n", sizeof(one), nw);
  pthread_mutex_unlock(&s->tcap.mutex);

  goto end;

aborted:
  /* for cleanup purpose */
  pthread_mutex_lock(&s->tcap.mutex);
  if (tcsess->aborted) {
    tid = MYCALLOC(1, sizeof(uint32_t));
    *tid = tcsess->ugw_tid;
    lfq_enqueue(s->tcap.dfq, tid); /* pointers are at least 32 bits long, information shouldn't be lost */
  }
  pthread_mutex_unlock(&s->tcap.mutex);
  sigtran_tcap_info_free(sinfo); /* we don't need it anymore, no more requests/response will come */
  sinfo = NULL;


end:
  if (msg) MYFREE(msg);

#if 0
  if (tcsess->aborted || ((tcsess->momt == MOMT_MO) && (flow == TCMessage_PR_end))) { /* MT sessions are not ended the same way */
    MYFREE(sinfo->tcsess);
    sinfo->tcsess = NULL;
  }
#endif

  if (sinfo && sinfo->usessinfo) {
    MYFREE(sinfo->usessinfo);
    sinfo->usessinfo = NULL;
  }

  pthread_exit(NULL);

  return NULL;
}

/* ati session handler thread */
void *ati_session_handler(void *data)
{
  FTRACE();
  int ret = -1;

  sigtran_tcap_info_t *sinfo = NULL;
  sigtran_t *s = NULL;
  ussd_session_t *usessinfo = NULL;
  tcap_session_t *tcsess = NULL;
  char *msg = NULL;
  int flow = 0;
  uint64_t one = 0UL;
  char q[2] = { 0 };
  size_t size = 0;
#define MAXURI 512
  char uribuf[MAXURI] = { 0 };
  int urilen = 0;
  char *escaped = NULL;
  //uri_t *url_handle = NULL;
  uint32_t *tid = NULL;
  ssize_t nw = 0;

  const char *err_resp = "0Service temporarily unavailable. Pleasae try later.";




  sinfo = data;
  if (!sinfo) goto end;
  usessinfo = sinfo->usessinfo;
  if  (!usessinfo) goto end;
  tcsess = sinfo->tcsess;
  if (!tcsess) goto end;
  s = sinfo->st;
  if (!s) goto end;

//  DTRACE("MAP Stack ID: %u, MAP Dialogue ID: %u\n", usessinfo->map_stack_id, usessinfo->dialogue_id);


  //ussd_session_dump(usessinfo);

//      uint8_t len = gsm_7bit_decode_n_ussd(usessinfo->ussd_string, sizeof(usessinfo->ussd_string), uinfo->ussd_String.buf, septets);

#define MAX_USSD_STRING 182
#ifndef UGWTEST
  q[1] = '\0';
  if (strchr(s->appurl, '?')) {
    q[0] = '\0'; /* nothing to add */
  } else {
    q[0] = '?'; /* add query string */
  }
  //url_handle = url_handle_new();
  //escaped = url_encode(url_handle, usessinfo->ussd_string, &size); /* we already have url handle, we can use it to encode */
  escaped = rawurlencode(usessinfo->ussd_string, usessinfo->ussd_string_len, &size); /* why use third party if you have a working version ? */
  if (escaped) {
    memset(uribuf, 0, sizeof(uribuf));
    urilen = snprintf(uribuf, sizeof(uribuf)-1,
       	"%s%s"
	"transactionID=%u&"
	"map_stack_id=%hu&"
	"dialogid=%hu&"
	"number=%s&"
	"text=%s&"
	"status=%s&"
	"momt=%s&"
	"error=%u",
       	s->appurl, q,
	tcsess->ugw_tid,
	usessinfo->map_stack_id,
	usessinfo->dialogue_id,
	usessinfo->msisdn,
	escaped,
	tcsess->flow_desc,
	tcsess->momt_desc,
	tcsess->error);
    MYFREE(escaped);
    //url_encode_free(escaped);
#ifdef DEBUG
    fprintf(stderr, "URI {%u}: [%s]\n", tcsess->ugw_tid, uribuf);
#endif
    msg = uri_get_contents(uribuf, urilen, &size);
#ifdef DEBUG
    fprintf(stderr, "RESP {%u}: [%s]\n", tcsess->ugw_tid, msg);
#endif
    if (msg && size > (MAX_USSD_STRING+1)) { /* FIXME: MAX USSD STRING + Prefix byte (only for GSM7 alphabet, next version should be more robust) */
      *(msg+MAX_USSD_STRING+1) = '\0';
      size = MAX_USSD_STRING;
#ifdef DEBUG
      fprintf(stderr, "RESP {%u} [TRIM]: [%s]\n", tcsess->ugw_tid, msg);
#endif
    }
    //fprintf(stderr, "Length: %d\nData: [%s]\n", size, msg);
    //MYFREE(contents);
  }
  //url_handle_free(url_handle);
#else /* UGWTEST */
  msg = MYSTRDUP(err_resp);
  size = strlen(msg);
#endif

  if (tcsess->aborted) goto aborted;

//  const char *endmsg = "0Service under maintenance. Please try again later.";
//  const char *contmsg = "1Type something";
//  char *msisdn = NULL;

  if (!msg || size <= 1) {
    if (msg) MYFREE(msg); /* maybe local API replied but the upstream didn't */
    msg = MYSTRDUP(err_resp);
    size = strlen(msg);
  }
  //msg = endmsg;
  if (msg && msg[0] == '1') {
    flow = TCMessage_PR_continue;
  } else {
    flow = TCMessage_PR_end;
    if (tcsess->momt == MOMT_MO) tcsess->aborted = 1;
  }

  TTRACE("<<< map: msisdn=%s, text=%s\n", tcsess->msisdn, msg+1);
  ret = tcap_msg_resp(sinfo, msg+1, NULL, flow); /* msisdn is NULL because in reply we don't need it */
  if (ret <= 0) goto end;

  //sinfo->comp_resp = ussd_notify_invoke(sinfo);
  /*
   * done, now send back to sigtran module to write to wire
   */

  /* sinfo->udt->data is properly filled up by tcap */
  one = 1UL;
  pthread_mutex_lock(&s->tcap.mutex);
  lfq_enqueue(s->tcap.q_fr_tcap, sinfo);
  if (tcsess->aborted) {
    tid = MYCALLOC(1, sizeof(uint32_t));
    *tid = tcsess->ugw_tid;
    lfq_enqueue(s->tcap.dfq, tid); /* pointers are at least 32 bits long, information shouldn't be lost */
  }
  nw = write(s->tcap.efd, &one, sizeof(one)); /* wake up the sigtran part to send response back */
  if (nw != sizeof(one)) DTRACE("Attempted to write %lu bytes, but wrote %ld bytes\n", sizeof(one), nw);
  pthread_mutex_unlock(&s->tcap.mutex);

  goto end;

aborted:
  /* for cleanup purpose */
  pthread_mutex_lock(&s->tcap.mutex);
  if (tcsess->aborted) {
    tid = MYCALLOC(1, sizeof(uint32_t));
    *tid = tcsess->ugw_tid;
    lfq_enqueue(s->tcap.dfq, tid); /* pointers are at least 32 bits long, information shouldn't be lost */
  }
  pthread_mutex_unlock(&s->tcap.mutex);
  sigtran_tcap_info_free(sinfo); /* we don't need it anymore, no more requests/response will come */
  sinfo = NULL;


end:
  if (msg) MYFREE(msg);

#if 0
  if (tcsess->aborted || ((tcsess->momt == MOMT_MO) && (flow == TCMessage_PR_end))) { /* MT sessions are not ended the same way */
    MYFREE(sinfo->tcsess);
    sinfo->tcsess = NULL;
  }
#endif

  if (sinfo && sinfo->usessinfo) {
    MYFREE(sinfo->usessinfo);
    sinfo->usessinfo = NULL;
  }

  pthread_exit(NULL);

  return NULL;
}

int sigtran_tcap_comp_parse(sigtran_tcap_info_t *sinfo)
{
  FTRACE();
  int ret = -1;

  tcap_session_t *tcsess = NULL;

  Invoke_t *inv = NULL;
  ReturnResult_t *rr = NULL;
  struct resultretres *resultretres = NULL;
  OPERATION_t *opCode = NULL;
  Parameter_t *parameter = NULL;
  Component_t *comp = NULL;


  if (!sinfo) goto end;

  tcsess = sinfo->tcsess;
  if (!tcsess) goto end;



  comp = sinfo->comp;
  if (!comp) goto aborted;


  switch (comp->present) {
    case Component_PR_invoke:
      inv = &comp->choice.invoke;
      tcsess->invokeid = inv->invokeID; /* decrement for response if not 'end' */
      opCode = &inv->opCode;
      parameter = inv->parameter;
      break;
    case Component_PR_returnResultLast:
      rr = &comp->choice.returnResultLast;
      tcsess->invokeid = rr->invokeID; /* decrement for response if not 'end' */
      resultretres = rr->resultretres;
      if (resultretres) {
	opCode = &resultretres->opCode;
	parameter = resultretres->parameter;
      }
      break;
    default:
      goto end;
      break;
  }


  if (parameter) sinfo->param = parameter;

  if (opCode && (opCode->present == OPERATION_PR_localValue)) {
    asn_INTEGER2long(&opCode->choice.localValue, (long *) &tcsess->opcode);
    if (tcsess->flow == TCMessage_PR_begin) {
      tcsess->end_opcode = tcsess->opcode; /* ending opcode should be equal to begin opcode */
      tcsess->end_invokeid = tcsess->invokeid; /* ending invokeid should be equal to begin invokeid */
    }
    /* parse parameter */
    //ret = sigtran_tcap_parameter_parse(sinfo);
  } else {
    tcsess->opcode = -1; /* Global Value (globalValue, OID) not supported (yet) */
    DTRACE("opCode NULL or globalValue not yet handled for opCode\n");
  }

  if (tcsess->opcode == -1) goto end;

aborted: // handle aborted session
  //tcsess->opcode = 0;
  //ret = sigtran_tcap_parameter_parse(sinfo);

  ret = sigtran_tcap_parameter_parse(sinfo);
end:

  return ret;
}


/* session continued by mobile station */
int sigtran_tcap_parse(sigtran_tcap_info_t *sinfo)
{
  FTRACE();

  int ret = -1;
  tcap_session_t *tcsess = NULL;
  Component_t *component = NULL;

  Begin_t *begin = NULL;
  Continue_t *Continue = NULL;
  End_t *end = NULL;
//  Abort_t *abort = NULL;
  uint16_t map_id = 0;
  uint16_t dialogue_id = 0;

  TCMessage_t *tcm = sinfo->tcm;
  if (!tcm) goto err;

  ret = sigtran_tcap_resolve_map_id(sinfo, &map_id, &dialogue_id);
  if (ret <= 0) {
    CRITICAL("*** MAP ID not resolved (maybe due to broken session), ignored!!!\n");
    goto err;
  }
  /* sinfo->tcsess is assigned by sigtran_tcap_resolve_map_id() */

  tcsess = sinfo->tcsess;
  if (!tcsess) goto err_ret;

  tcsess->flow = tcm->present; /* will be updated throughout the transaction */
  switch (tcm->present) {
    case TCMessage_PR_begin:
      tcsess->momt = MOMT_MO;
      strcpy(tcsess->momt_desc, "mo");
      strcpy(tcsess->flow_desc, "begin"); /* will be updated throughout the transaction */
      begin = &tcm->choice.begin;
      tcsess->hlr_tid = 0;
      memcpy(&tcsess->hlr_tid, begin->otid.buf, begin->otid.size); /* will NOT be updated */
      TTRACE(">>> tcap: begin (otid=%x)\n", tcsess->hlr_tid);
      //DTRACE("Length of hlr_tid = %d\n", begin->otid.size);
      tcsess->dialog_pdu_needed = 1;
      if (!begin->components || !begin->components->list.count) {
	ret = -1;
	goto err;
      }
      component = begin->components->list.array[0];
      break;
    case TCMessage_PR_continue:
      strcpy(tcsess->flow_desc, "continue"); /* will be updated throughout the transaction */
      Continue = &tcm->choice.Continue;
      tcsess->hlr_tid = 0;
      memcpy(&tcsess->hlr_tid, Continue->otid.buf, Continue->otid.size);
      TTRACE(">>> tcap: continue (otid=%x, dtid=%x)\n", tcsess->hlr_tid, tcsess->ugw_tid);
      if (!Continue->components || !Continue->components->list.count) {
	ret = -1;
	goto err;
      }
      component = Continue->components->list.array[0];
      break;
    case TCMessage_PR_end:
      strcpy(tcsess->flow_desc, "end"); /* will be updated throughout the transaction */
      end = &tcm->choice.end;
      tcsess->aborted = 1; /* similar to aborted session */
      TTRACE(">>> tcap: end (dtid=%x)\n", tcsess->ugw_tid);
      if (!end->components || !end->components->list.count) {
	DTRACE("Component portion missing. Still proceeding.\n");
	tcsess->error = 1;
	//ret = -1;
	//goto err;
      } else {
	component = end->components->list.array[0];
      }
      break;
    case TCMessage_PR_abort: /* to 3rd party we show just 'end' */
      TTRACE(">>> tcap: abort (otid=%x, dtid=%x) {cached}\n", tcsess->hlr_tid, tcsess->ugw_tid);
      //TTRACE("tcap: aborted (otid=%x, dtid=%x) {cached}\n", tcsess->ugw_tid);
      strcpy(tcsess->flow_desc, "end"); /* will be updated throughout the transaction */
      //abort = &tcm->choice.abort; /* we don't go to decode that much the aborted packets */
      tcsess->aborted = 1;
      break;
    default:
      DTRACE("Unknown TCAP packet. Will not process.\n");
      ret = -1;
      goto err;
      break;
  }


  sinfo->comp = component;

  DTRACE("Going to put to queue of MAP STACK [%u]\n", map_id);
  lfq_enqueue(sinfo->st->tcap.map->mq[map_id], sinfo);
  sem_post(&sinfo->st->tcap.map->sem[map_id]);

  return ret;

err:

err_ret:
  if (map_id || dialogue_id) {
    map_del_dialogue(sinfo->st->tcap.map, map_id, dialogue_id);
  }
  /* in case of error we are stuck, nothing to be done */

  return ret;
}


int sigtran_tcap_process(sigtran_tcap_info_t *sinfo)
{
  FTRACE();

  int ret = 0;
  TCMessage_t *pdu = tcap_decode(sinfo->udt->data, sinfo->udt->data_len);
  if (!pdu) {
    DTRACE("*** TCAP PDU DECODE FAILED. SOMETHING MUST BE WRONG!***\n");
    hexdump(sinfo->udt->data, sinfo->udt->data_len);
    ret = -1;
    goto err_ret;
  }
  //tcap_print(pdu);

  //llist_t *kvs = NULL;
  //kv_t *kv = NULL;

  //kv = MYCALLOC(1, sizeof(kv_t));
  //MYFREE(kv);


  /* {begin,end,continue,abort} */
  sinfo->tcm = pdu;
  ret = sigtran_tcap_parse(sinfo);
  if (ret < 0) goto err_ret;

  return ret;

err_ret:
  sigtran_tcap_info_free(sinfo);

  return ret;
}

/* worker thread for sigtran_tcap bridge */
void *sigtran_tcap_worker(void *st)
{
  FTRACE();
  sigtran_t *s = st;
  sigtran_tcap_info_t *sinfo = NULL;


  s->tcap.map = map_init(s);

  while (1) {
    DTRACE("Waiting for data from SIGTRAN\n");
    sem_wait(&s->tcap.lock);
    DTRACE("Data available from SIGTRAN. Going to process.\n");

    sinfo = lfq_dequeue(s->tcap.q_to_tcap);
    if (sinfo) {
      //sccp_dump_udt(sinfo->udt);

      /* fill up sinfo with data, replacing old contents */
      if (sigtran_tcap_process(sinfo) < 0) {
	CRITICAL("*** TCAP Process Failed\n");
	/* send reply back to communication system to notify user */
      }
#if 0
  uint32_t nextpos = 0;
      /* just to check if encoding and decoding works */
      octet *buf = NULL;
      /* checking if encoding and decoding works */
      buf = sccp_udt2octet(sinfo->udt, &nextpos);
      MYFREE(sinfo->udt);
      sinfo->udt = sccp_octet2udt(buf, nextpos, &nextpos);
      if (sinfo->udt) sccp_dump_udt(sinfo->udt);
      MYFREE(buf);
#endif
    }
  }
  /* never reach here */

  pthread_exit(NULL);

  return NULL;
}

static map_t *map_init(sigtran_t *s)
{
  FTRACE();

  long i = 0;
  size_t n = 0;
  map_t *map = NULL;

  pthread_t tid = 0;
#if 0
  pthread_attr_t attr;
#endif

  map_worker_t *mw = NULL;

#if 0
  signal(SIGPIPE, handle_signal);
#endif

//  url_system_init(); /* initialize curl subsystem */

  map = MYCALLOC(1, sizeof(map_t));
  map->nmq = s->tcap.nmaps;
  map->st = s;

  DTRACE("Going to create %lu MAP workers\n", map->nmq);

  n = map->nmq;
#if 0
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif
  map->mq = MYCALLOC(n, sizeof(struct lfq *));
  map->dialogues = MYCALLOC(n, sizeof(iarray_t *));
  map->rwlocks = MYCALLOC(n, sizeof(pthread_rwlock_t));
  map->sem = MYCALLOC(n, sizeof(sem_t));
  map->fq = MYCALLOC(n, sizeof(struct lfq *));
//  map->last_dialogue = MYCALLOC(n, sizeof(uint16_t));
  for (i = 0; i < n; ++i) {
    mw = MYCALLOC(1, sizeof(map_worker_t));
    mw->map = map;
    mw->map_id = (uint16_t) i;
    if (pthread_create(&tid, NULL, map_stack_start, mw) == 0) {
      pthread_detach(tid);
      map->mq[i] = lfq_new();
      iarray_init(&map->dialogues[i]);
      sem_init(&map->sem[i], 0, 0);
      //map->last_dialogue[i] = 0;
    }
  }

#if 0
  pthread_attr_destroy(&attr);
#endif

//  url_system_cleanup();

  return map;
}

/* lookup a tcap session, if 'begin' then it allocates a new one */
int sigtran_tcap_resolve_map_id(sigtran_tcap_info_t *sinfo, uint16_t *map_id, uint16_t *dialogue_id)
{
  FTRACE();
  uint16_t tmp_map_id = 0;
  uint16_t tmp_dlg_id = 0;
//  uint16_t dialogue_id = 0;
  int ret = -1;
  tcap_session_t *tcsess = NULL;
  uint32_t ugw_tid = 0;
  uint32_t *tid = NULL;

  /*
  Begin_t *begin = NULL;
  */
  Continue_t *Continue = NULL;
  End_t *end = NULL;
  Abort_t *abort = NULL;
  TCMessage_t *tcm = NULL;




  if (!sinfo) return ret;

  /* cleanup should be done at first, so that we don't resolve to some id which is in free queue already by some thread */
  /* this usually doesn't happen, but who knows under some situation MS might send the packet again */
  /* release freed map dialogue id from map stack */
//  DTRACE("Cleaning up Dialogue IDs (for MO sessions) {begin/continue->end}\n");
  /* clean up ended sessions */
  while ((tid = lfq_dequeue(sinfo->st->tcap.dfq))) { /* MAP threads calls one by one, and this function is safe for single producer and single consumer without locking */
    tmp_map_id = tid2map_id(*tid);
    tmp_dlg_id = tid2dialogue_id(*tid);
    MYFREE(tid);
    map_del_dialogue(sinfo->st->tcap.map, tmp_map_id, tmp_dlg_id);
  }


  tcm = sinfo->tcm;
  if (!tcm) return ret;

  //tcsess = sinfo->tcsess;
  switch (tcm->present) {
    case TCMessage_PR_begin: /* no ugw_tid found, get next one */
      DTRACE("Session Begins by User/Network\n");
      /*
      begin = &tcm->choice.begin;
      tcsess = MYCALLOC(1, sizeof(tcap_session_t));
      if (!tcsess) {
	ret = -1;
	break;
      }
      */
      *map_id = sinfo->st->tcap.nextid++ % sinfo->st->tcap.nmaps; /* no probelm if called by multiple threads, any value will work */
      //sinfo->st->tcap.nextid++;
      ret = map_set_next_dialogue(sinfo->st->tcap.map, *map_id, (iarray_val_t *) &tcsess, dialogue_id); /* allocate a new tcap session and sets to tcsess */
      if (ret == -1) {
	CRITICAL("*** MAP Dialogue ID not available (maybe exhausted). Need additional license!!!\n");
	break;
      }

      sinfo->tcsess = tcsess;
      tcsess->start_time = tcsess->heartbeat = time(NULL);
      //tcsess->hlr_tid = 0;
      //memcpy(&tcsess->hlr_tid, begin->otid.buf, begin->otid.size); /* will NOT be updated */

      tcsess->ugw_tid = get_tid(*map_id, *dialogue_id);
      DTRACE("UGW TID: %u\n", tcsess->ugw_tid);
      DTRACE("MAP STACK ID: %hu\n", *map_id);
      DTRACE("MAP DIALOG ID: %hu\n", *dialogue_id);
      ret = 1;
      break;
    case TCMessage_PR_continue: /* ugw_tid found, resolve from it */
      DTRACE("Session Continued by User/Network\n");
      Continue = &tcm->choice.Continue;
      memcpy(&ugw_tid, Continue->dtid.buf, Continue->dtid.size); /* will NOT be updated */
      *map_id = tid2map_id(ugw_tid);
      *dialogue_id = tid2dialogue_id(ugw_tid);
      ret = map_get_dialogue(sinfo->st->tcap.map, *map_id, *dialogue_id, (iarray_val_t *) &tcsess);
      if (ret == -1) break;
      sinfo->tcsess = tcsess;
      tcsess->heartbeat = time(NULL);
      DTRACE("UGW TID: %u\n", tcsess->ugw_tid);
      DTRACE("MAP STACK ID: %hu\n", *map_id);
      DTRACE("MAP DIALOG ID: %hu\n", *dialogue_id);
      ret = 1;
      break;
    case TCMessage_PR_end: /* ugw_tid found, resolve from it */
      DTRACE("Session Ended by User/Network\n");
      end = &tcm->choice.end;
      memcpy(&ugw_tid, end->dtid.buf, end->dtid.size); /* will NOT be updated */
      *map_id = tid2map_id(ugw_tid);
      *dialogue_id = tid2dialogue_id(ugw_tid);
      ret = map_get_dialogue(sinfo->st->tcap.map, *map_id, *dialogue_id, (iarray_val_t *) &tcsess);
      if (ret == -1) break;
      sinfo->tcsess = tcsess;
      tcsess->heartbeat = time(NULL);
      DTRACE("UGW TID: %u\n", tcsess->ugw_tid);
      DTRACE("MAP STACK ID: %hu\n", *map_id);
      DTRACE("MAP DIALOG ID: %hu\n", *dialogue_id);
      //map_del_dialogue(sinfo->st->tcap.map, *map_id, dialogue_id);
      //sinfo->tcsess = NULL;
      ret = 1;
      break;
    case TCMessage_PR_abort: /* ugw_tid found, resolve from it */
      DTRACE("Session Aborted by User/Network\n");
      abort = &tcm->choice.abort;
      memcpy(&ugw_tid, abort->dtid.buf, abort->dtid.size); /* will NOT be updated */
      *map_id = tid2map_id(ugw_tid);
      *dialogue_id = tid2dialogue_id(ugw_tid);
      ret = map_get_dialogue(sinfo->st->tcap.map, *map_id, *dialogue_id, (iarray_val_t *) &tcsess);
      if (ret == -1) break;
      sinfo->tcsess = tcsess;
      tcsess->heartbeat = time(NULL);
      DTRACE("UGW TID: %u\n", tcsess->ugw_tid);
      DTRACE("MAP STACK ID: %hu\n", *map_id);
      DTRACE("MAP DIALOG ID: %hu\n", *dialogue_id);
      //map_del_dialogue(sinfo->st->tcap.map, *map_id, dialogue_id);
      //sinfo->tcsess = NULL;
      ret = 1;
      break;
    default:
      break;
  }


  //DTRACE("Returns\n");

  return ret;
}

void *map_stack_start(void *info)
{
  FTRACE();
  map_worker_t *mw = NULL;
  map_t *map = NULL;
  uint16_t map_id = 0;
  int ret = -1;

  mw = info;
  if (mw) {
    map = mw->map;
    map_id = mw->map_id;
    MYFREE(mw); /* we don't need this, it is just a skeleton to contain the needed information */
  } else {
    goto end;
  }

  pthread_rwlock_init(&map->rwlocks[map_id], NULL);

  DTRACE("Starting MAP Stack [%hu]\n", map_id);

  sigtran_tcap_info_t *sinfo = NULL;
//  tcap_session_t *tcsess = NULL;
//  Invoke_t *cinv = NULL;
//  Component_t *comp = NULL;
  while (1) {
    DTRACE("[%u] Waiting for packets from TCAP worker thread.\n", map_id);
    sem_wait(&map->sem[map_id]);
    sinfo = lfq_dequeue(map->mq[map_id]); /* send with length information, maybe ASN parameter */

    if (sinfo) {
      DTRACE("[%u] received from TCAP worker thread.\n", map_id);
//      tcsess = sinfo->tcsess;
//      comp = sinfo->comp;
      //if (!comp) continue; /* nothing to process */
      ret = sigtran_tcap_comp_parse(sinfo);
      if (ret < 0) {
	DTRACE("[%u] Error processing received packet.\n", map_id);
      }
    }
  }

end:

  CRITICAL("*** MAP worker thread [map_id=%u] going to return. This should NOT happen.\n", map_id);

  pthread_exit(NULL);

  return NULL;
}

void tcap_session_dump(tcap_session_t *info)
{
  if (info) {
    DTRACE("flow=%s [%u]\n", info->flow_desc, info->flow);
    DTRACE("hlr_tid=%u\n", info->hlr_tid);
    DTRACE("ugw_tid=%u\n", info->ugw_tid);
    //DTRACE("component=%s\n", info->component_desc);
    DTRACE("invokeid=%d\n", info->invokeid);
    DTRACE("opcode=%ld\n", info->opcode);
  }
}

void ussd_session_dump(ussd_session_t *info)
{
  if (info) {
    DTRACE("map_stack_id=%u\n", info->map_stack_id);
    DTRACE("dialogue_id=%u\n", info->dialogue_id);
    if (info->ussd_string_len > 0) DTRACE("ussd string=%s [%u]\n", info->ussd_string, info->ussd_string_len);
    if (info->msisdn_len > 0) DTRACE("msisdn=%s [%u]\n", info->msisdn, info->msisdn_len);
  }
}
