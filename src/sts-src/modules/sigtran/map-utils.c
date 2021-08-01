/*
 * map-utils.c
 */

#include "map-utils.h"
//#include <math.h>		/* ceil(), etc. */


/* free memory allocated by sigtran_create_map_comp() */
void ussd_session_comp_free(Component_t *comp)
{
  FTRACE();

  ReturnResult_t *rr = NULL;
  Invoke_t *inv = NULL;

  if (comp) {

    switch (comp->present) {
      case Component_PR_invoke:
	inv = &comp->choice.invoke;
	if (inv->parameter) {
	  ASN_FREE(asn_DEF_ANY, inv->parameter, 0);
	}
	ASN_FREE_INTEGER(&inv->opCode.choice.localValue);
	break;
      case Component_PR_returnResultLast:
	rr = &comp->choice.returnResultLast;
	if (rr->resultretres) {
	  if (rr->resultretres->parameter) {
	    ASN_FREE_PTR(asn_DEF_ANY, rr->resultretres->parameter);
	  }
	  ASN_FREE_INTEGER(&rr->resultretres->opCode.choice.localValue);
	  MYFREE(rr->resultretres);
	}
	break;
      default:
	break;
    }
    MYFREE(comp);
  }

}

void ati_session_comp_free(Component_t *comp)
{
  ussd_session_comp_free(comp);
}


Component_t *sigtran_create_map_comp(tcap_session_t *tcsess,
    int comp_type, asn_TYPE_descriptor_t *td, void *sptr)
{
  FTRACE();

  Component_t *comp = NULL;
  ReturnResult_t *rr = NULL;
  Invoke_t *inv = NULL;

  comp = MYCALLOC(1, sizeof(*comp));
  //memset(comp, 0, sizeof(*comp)); /* MYCALLOC() already initializes with zero */

  comp->present = comp_type;
  switch (comp_type) {
    case Component_PR_invoke:
      inv = &comp->choice.invoke;
      inv->invokeID = tcsess->invokeid;
      inv->opCode.present = OPERATION_PR_localValue;
      asn_long2INTEGER(&inv->opCode.choice.localValue, tcsess->opcode); /* should call ASN_FREE_INTEGER(ptr) when done */
      if (td && sptr) {
	inv->parameter = ANY_new_fromType(td, sptr);
      }
      break;
    case Component_PR_returnResultLast:
      rr = &comp->choice.returnResultLast;
      rr->invokeID = tcsess->invokeid;
      rr->resultretres = MYCALLOC(1, sizeof(struct resultretres));
      rr->resultretres->opCode.present = OPERATION_PR_localValue;
      asn_long2INTEGER(&rr->resultretres->opCode.choice.localValue, tcsess->opcode); /* should call ASN_FREE_INTEGER(ptr) when done */
      if (td && sptr) {
	rr->resultretres->parameter = ANY_new_fromType(td, sptr);
      }
      break;
    default:
      break;
  }

  return comp;
}

Component_t *ati_session_comp_build(tcap_session_t *tcsess, const char *gsmscf_addr, const char *msisdn, int flow, int notify_only)
{
  FTRACE();

  //USSD_Arg_t *uinfo = NULL;
  AnyTimeInterrogationArg_t *uinfo = NULL;
  Component_t *comp = NULL;
  int comp_type = 0;

  uinfo = map_build_ati_arg(msisdn, gsmscf_addr);
  if (!uinfo) return NULL;

  comp_type = Component_PR_invoke; /* defaulting to 'Invoke' */
//  long opcode = GSMMAPOperationLocalvalue_unstructuredSS_Notify; /* default, will be set below */

  switch (flow) {
    case TCMessage_PR_begin:
      tcsess->opcode = GSMMAPOperationLocalvalue_anyTimeInterrogation;
      break;
    default:
      break;
  }
  /*
  comp = sigtran_create_map_invoke(sinfo, GSMMAPOperationLocalvalue_unstructuredSS_Notify,
      &asn_DEF_USSD_Arg, uinfo);
  comp = sigtran_create_map_invoke(sinfo, GSMMAPOperationLocalvalue_processUnstructuredSS_Request,
      &asn_DEF_USSD_Arg, uinfo);
      */
  comp = sigtran_create_map_comp(tcsess, comp_type, &asn_DEF_AnyTimeInterrogationArg, uinfo);
  //xer_fprint(stdout, &asn_DEF_Component, comp);


  //map_free_ussd_arg(uinfo);
  map_free_ati_arg(uinfo);

  return comp;
}


/* gsmscf_addr == tcsess->ugw_gt */
AnyTimeInterrogationArg_t *map_build_ati_arg(const char *msisdn, const char *gsmscf_addr)
{
  FTRACE();

  //USSD_Arg_t *uinfo = NULL;
  AnyTimeInterrogationArg_t *uinfo = NULL;
  uint8_t tbuf[SIGTRAN_MTU] = { 0 };
  //int utf8len = 0;
  uint8_t octets_written = 0;
  //int septets_written = 0;
  //const char dcs[] = { 0x0f };

  if (msisdn) {
    uinfo = MYCALLOC(1, sizeof(*uinfo));
    uinfo->subscriberIdentity.present = SubscriberIdentity_PR_msisdn;

    memset(tbuf, 0, sizeof(tbuf));
    //utf8len = strlen(msg); /* need to use utf8 routines to properly count */
    //gsm_7bit_encode_n_ussd(tbuf, sizeof(tbuf), msg, &octets_written);
    //septets_written = utf8_to_gsm7((cbytes_t) msg, utf8len, tbuf, 0);
    //octets_written = (int) ceil(septets_written * 7 / 8);

    //OCTET_STRING_fromBuf(&uinfo->ussd_DataCodingScheme, dcs, sizeof(dcs));
    //OCTET_STRING_fromBuf(&uinfo->ussd_String, (char *) tbuf, octets_written);

    memset(tbuf, 0, sizeof(tbuf));
    encode_msisdn(msisdn, (uint8_t) strlen(msisdn), tbuf, (uint8_t *) &octets_written);
    if (octets_written > 0) {
      OCTET_STRING_fromBuf(&uinfo->subscriberIdentity.choice.msisdn, (char *) tbuf, octets_written);
      //uinfo->msisdn = OCTET_STRING_new_fromBuf(&asn_DEF_ISDN_AddressString, (char *) tbuf, octets_written);
    }
    NULL_t *rinfo = MYCALLOC(1, sizeof(*rinfo)); // TODO: FREE IT
    *rinfo = 1;
    uinfo->requestedInfo.locationInformation = rinfo;

    memset(tbuf, 0, sizeof(tbuf));
    encode_msisdn(gsmscf_addr, (uint8_t) strlen(gsmscf_addr), tbuf, (uint8_t *) &octets_written);
    //encode_called_party(gsmscf_addr, strlen(gsmscf_addr), tbuf, &octets_written);
    OCTET_STRING_fromBuf(&uinfo->gsmSCF_Address, (char *) tbuf, octets_written);
  }

  return uinfo;
}

Component_t *ussd_session_comp_build(tcap_session_t *tcsess, const char *msg, const char *msisdn, int flow, int notify_only)
{
  FTRACE();

  USSD_Arg_t *uinfo = NULL;
  Component_t *comp = NULL;
  int comp_type = 0;

  uinfo = map_build_ussd_arg(msg, msisdn);
  if (!uinfo) return NULL;

  comp_type = Component_PR_invoke; /* defaulting to 'Invoke' */
//  long opcode = GSMMAPOperationLocalvalue_unstructuredSS_Notify; /* default, will be set below */

  switch (flow) {
    case TCMessage_PR_begin:
      if (notify_only) {
	tcsess->opcode = GSMMAPOperationLocalvalue_unstructuredSS_Notify;
      } else {
	tcsess->opcode = GSMMAPOperationLocalvalue_unstructuredSS_Request;
      }
      break;
    case TCMessage_PR_continue:
      if (notify_only) { /* for MT sessions trying to 'end' (invoke) */
	tcsess->opcode = GSMMAPOperationLocalvalue_unstructuredSS_Notify;
      } else {
	tcsess->opcode = GSMMAPOperationLocalvalue_unstructuredSS_Request;
      }
      ++tcsess->invokeid;
      break;
    case TCMessage_PR_end:
      if ((tcsess->momt == MOMT_MO) && tcsess->end_opcode) { /* MO USSD */
	comp_type = Component_PR_returnResultLast;
	tcsess->opcode = tcsess->end_opcode;
	tcsess->invokeid = tcsess->end_invokeid;
      } else { /* MT USSD */
	tcsess->opcode = GSMMAPOperationLocalvalue_unstructuredSS_Notify;
	++tcsess->invokeid;
      }
      break;
    default:
      break;
  }
  /*
  comp = sigtran_create_map_invoke(sinfo, GSMMAPOperationLocalvalue_unstructuredSS_Notify,
      &asn_DEF_USSD_Arg, uinfo);
  comp = sigtran_create_map_invoke(sinfo, GSMMAPOperationLocalvalue_processUnstructuredSS_Request,
      &asn_DEF_USSD_Arg, uinfo);
      */
  comp = sigtran_create_map_comp(tcsess, comp_type, &asn_DEF_USSD_Arg, uinfo);
  //xer_fprint(stdout, &asn_DEF_Component, comp);


  map_free_ussd_arg(uinfo);

  return comp;
}


USSD_Arg_t *map_build_ussd_arg(const char *msg, const char *msisdn)
{
  FTRACE();

  USSD_Arg_t *uinfo = NULL;
  uint8_t tbuf[SIGTRAN_MTU] = { 0 };
  //int utf8len = 0;
  int octets_written = 0;
  //int septets_written = 0;
  const char dcs[] = { 0x0f };

  if (msg) {
    uinfo = MYCALLOC(1, sizeof(*uinfo));

    memset(tbuf, 0, sizeof(tbuf));
    //utf8len = strlen(msg); /* need to use utf8 routines to properly count */
    gsm_7bit_encode_n_ussd(tbuf, sizeof(tbuf), msg, &octets_written);
    //septets_written = utf8_to_gsm7((cbytes_t) msg, utf8len, tbuf, 0);
    //octets_written = (int) ceil(septets_written * 7 / 8);

    OCTET_STRING_fromBuf(&uinfo->ussd_DataCodingScheme, dcs, sizeof(dcs));
    OCTET_STRING_fromBuf(&uinfo->ussd_String, (char *) tbuf, octets_written);

    if (msisdn) {
      memset(tbuf, 0, sizeof(tbuf));
      encode_msisdn(msisdn, (uint8_t) strlen(msisdn), tbuf, (uint8_t *) &octets_written);
      if (octets_written > 0) {
	uinfo->msisdn = OCTET_STRING_new_fromBuf(&asn_DEF_ISDN_AddressString, (char *) tbuf, octets_written);
      }
    }
  }

  return uinfo;
}

void map_free_ussd_arg(USSD_Arg_t *arg)
{
  FTRACE();

  if (arg) {
    
    ASN_FREE_DATA(asn_DEF_USSD_DataCodingScheme, &arg->ussd_DataCodingScheme); /* don't free the ptr */
    ASN_FREE_DATA(asn_DEF_USSD_String, &arg->ussd_String); /* don't free the ptr */
    if (arg->msisdn) {
      ASN_FREE_PTR(asn_DEF_ISDN_AddressString, arg->msisdn); /* free the ptr as well */
    }
    MYFREE(arg);
  }
}

void map_free_ati_arg(AnyTimeInterrogationArg_t *arg)
{
  FTRACE();

  if (arg) {
    MYFREE(arg);
  }
}

