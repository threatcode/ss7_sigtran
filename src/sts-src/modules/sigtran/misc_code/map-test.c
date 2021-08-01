/*
 * map-test.c
 */
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <map/Component.h>

#include "utils.h"


void map_decode(const void *buf, size_t len)
{
  asn_dec_rval_t rval;
  Component_t *pdu = NULL; /* Note this 0! (Forgetting to properly initialize the pointing to a destination structure is a major source of support requests) */

  rval = ber_decode(0,
      &asn_DEF_Component,
      (void **) &pdu, /* Decoder moves the pointer */
      buf, len);

  if (rval.code == RC_OK) {
    fprintf(stderr, "Decoded successfully\n");
    xer_fprint(stdout, &asn_DEF_Component, pdu);

#if 0
    int i = 0;
    uint8_t buf[256];
    asn_enc_rval_t er;  /* Encoder return value */
    cmp = pdu->choice.begin.components->list.array[i];
    if (cmp->present == Component_PR_invoke) {
      fprintf(stdout, "Component type Invoke\n");
      er = der_encode_to_buffer(&asn_DEF_Component, cmp, buf, sizeof(buf));
      if (er.encoded > 0) {
	fprintf(stdout, "Encoded successfully, %ld bytes\n", er.encoded);
	hexdump(buf, er.encoded);
      } else {
	fprintf(stdout, "Failed to encode\n");
      }
    }
    /*
    Invoke_t *ipdu = NULL;
    ber_decode(0,
	&asn_DEF_Invoke,
	(void **) &ipdu,
	pdu->choice.begin.components->list, pdu->choice.begin.components.invoke.len);
	*/
#endif
  } else {
    /* Free partially decoded rect */
    fprintf(stderr, "Decode failed\n");
  }
  asn_DEF_Component.free_struct(&asn_DEF_Component, pdu, 0);
}

int main(void)
{
  char buf[256];
  int fd = open("map-bytes.bin", O_RDONLY);
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
  map_decode(buf, len);

  return 0;
}
