/*
 * tcap-test.c
 */
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <TCMessage.h>
#include <Component.h>

#include "utils.h"
#include "tcap.h"
#include <MAP-DialoguePDU.h>
#include <MAP-OpenInfo.h>


void tcap_process(const void *buf, size_t len)
{
  TCMessage_t *pdu = NULL; /* Note this 0! (Forgetting to properly initialize the pointing to a destination structure is a major source of support requests) */

  out_t out;
  int i;
  char obuf[256];

  pdu = tcap_decode(buf, len);

  if (pdu) {

    fprintf(stderr, "Decoded successfully\n");
    tcap_print(pdu);
    OUTPUT_BUFFER_INIT(&out, obuf);
    i = tcap_extract_from_struct(pdu, "begin.components.0.invoke.opCode.localValue", &out);
    fprintf(stdout, "tcap_extract opcode: returned %i, value %.*s\n", i, (int) out.used, out.buf);

    OUTPUT_BUFFER_INIT(&out, obuf);
    i = tcap_extract_from_struct(pdu, "begin.otid", &out);
    fprintf(stdout, "tcap_extract otid: returned %i, value %.*s\n", i, (int) out.used, out.buf);

    /*
    OUTPUT_BUFFER_INIT(&out, obuf);
    i = tcap_extract_from_struct(pdu, "begin.dialoguePortion.dialog.dialogueRequest.user-information", &out);
    fprintf(stdout, "tcap_extract dialogueRequest.user-information: returned %i, value %.*s\n", i, (int) out.used, out.buf);
    */

#if 0
    switch (pdu->choice.begin.dialoguePortion->dialog.present) {
      case DialoguePDU_PR_dialogueRequest:
	fprintf(stdout, "DialogueRequest\n");
	/* AARQ-apdu */
	struct user_information *uinfo = pdu->choice.begin.dialoguePortion->dialog.choice.dialogueRequest.user_information;
	//hexdump(uinfo->list.array[0], uinfo->list.array[0]->size);
	MAP_DialoguePDU_t *dpdu = NULL; /* must initialize to NULL otherwise things will behave strangely */
	//ANY_to_type(uinfo->list.array[0], &asn_DEF_MAP_DialoguePDU, (void **) &dpdu);
	ber_decode(0, &asn_DEF_MAP_DialoguePDU, (void **) &dpdu, uinfo->list.array[0]->buf+15, uinfo->list.array[0]->size-15);
	if (dpdu == NULL) {
	  fprintf(stdout, "Failed to convert to dialogue pdu\n");
	  asn_DEF_MAP_DialoguePDU.free_struct(&asn_DEF_MAP_DialoguePDU, dpdu, 0);
	} else {
	  xer_fprint(stdout, &asn_DEF_MAP_DialoguePDU, dpdu);

	  if (dpdu->present == MAP_DialoguePDU_PR_map_open) {
	    xer_fprint(stdout, &asn_DEF_MAP_OpenInfo, &dpdu->choice.map_open);
	  }

	  asn_DEF_MAP_DialoguePDU.free_struct(&asn_DEF_MAP_DialoguePDU, dpdu, 0);
	}
	break;
      case DialoguePDU_PR_dialogueResponse:
	fprintf(stdout, "DialogueResponse\n");
	break;
      case DialoguePDU_PR_dialogueAbort:
	fprintf(stdout, "DialogueAbort\n");
	break;
      default:
	break;
    }
#endif

    OUTPUT_BUFFER_INIT(&out, obuf);
    i = tcap_extract_from_struct(pdu, "begin.components.0.invoke.parameter", &out);
    fprintf(stdout, "tcap_extract invoke.parameter: returned %i, value %.*s\n", i, (int) out.used, out.buf);
    /*
    USSD_Arg_t *ussd = ussd_decode(out.buf, out.used);
    if (!ussd) {
      fprintf(stdout, "Decode of USSD Failed\n");
    } else {
      ussd_print(ussd);
    }
    ussd_free(ussd);
    */

    if (pdu->present == TCMessage_PR_begin) { /* Begin */
      int cs = pdu->choice.begin.components->list.count;
      Component_t *cmp;
      fprintf(stdout, "Total %d components\n", cs);
      int i = 0;
      octet ebuf[256];
      asn_enc_rval_t er;  /* Encoder return value */
      for (i = 0; i < cs; ++i) {
	cmp = pdu->choice.begin.components->list.array[i];
	if (cmp->present == Component_PR_invoke) {
	  fprintf(stdout, "Component type Invoke\n");
	  er = der_encode_to_buffer(&asn_DEF_Component, cmp, ebuf, sizeof(ebuf));
	  if (er.encoded > 0) {
	    fprintf(stdout, "Encoded successfully, %ld bytes\n", er.encoded);
	    hexdump(ebuf, er.encoded);

	  } else {
	    fprintf(stdout, "Failed to encode\n");
	  }
	}
      }
      /*
	 Invoke_t *ipdu = NULL;
	 ber_decode(0,
	 &asn_DEF_Invoke,
	 (void **) &ipdu,
	 pdu->choice.begin.components->list, pdu->choice.begin.components.invoke.len);
	 */
    }
    tcap_free(pdu);
  } else {
    /* Free partially decoded rect */
    fprintf(stderr, "Decode failed\n");
  }
}

int main(void)
{
  char buf[256];
  int fd = open("tcap-bytes.bin", O_RDONLY);
  if (fd == -1) {
    perror("open");
    return 1;
  }

  off_t len = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  ssize_t nr = read(fd, buf, sizeof(buf));
  if (len != nr) {
    perror("read");
  }
  close(fd);
  tcap_process(buf, len);

  return 0;
}
