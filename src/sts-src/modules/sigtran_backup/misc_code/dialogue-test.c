/*
 * dialogue-test.c
 */

/* construct DialoguePDU wwith AARQ */
/* destref == msisdn of the user
 * origref == gt of the gw
 */
#include "dialogue-utils.h"

int main(void)
{
  ExternalPDU_t *ext = NULL;

  //DialoguePDU_t *dial = calloc(1, sizeof(*dial));
  char *destnum = "8801534619955";
  char *srcnum = "880150159935";
  ext = ussd_dialogue_request_build(destnum, srcnum);
  xer_fprint(stdout, &asn_DEF_ExternalPDU, ext);

  ussd_dialogue_request_free(ext);

  return 0;
}
