/*
 * test-config.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>



int main(void)
{
  int ret = -1;
  char servaddr_str[20] = { 0 };
  int servaddr_port = 2905;
  char cliaddr_str[20] = { 0 };
  int cliaddr_port = 2905;
  uint32_t ugw_pc = 0; /* ussd gw (asp) point code */
  uint32_t msc_pc = 0; /* msc point code */
  uint8_t ugw_ssn = 147; /* gsmSCF (MAP) */
  //uint8_t ugw_ssn = 5; /* MAP */
  uint8_t hlr_ssn = 6; /* hlr */
  char ugw_gt[20] = { 0 };
  char hlr_gt[20] = { 0 }; /* Fixed HLR GT (for MT) */
  //char hlr_gt[] = "880150158821"; /* Load Balancing HLR GT */
  //char hlr_gt[] = "880150158822"; /* Load Balancing HLR GT */
  //char hlr_gt[] = "880150159840"; /* Load balancing HLR GT */
  char appurl[512] = { 0 };

#define CFGFILE "sigtran.cfg"
  FILE *cfgfp = NULL;
  char cbuf[512] = { 0 };
  char ckey[256] = { 0 };
  char cval[256] = { 0 };
  uint8_t cbuflen = 0;
  char *cptr = NULL;
  int coffset = 0;

  cfgfp = fopen(CFGFILE, "r");
  if (!cfgfp) {
    fprintf(stderr, "*** CONFIGURATION FILE MISSING [" CFGFILE "] ***\n");
    ret = -1;
    goto err_ret;
  }

  /* file format:
   * msc_ip=10.21.11.2
   * msc_port=3053
   * gw_ip=10.21.193.66
   * gw_port=2905
   * msc_pc=2500
   * gw_pc=2228
   * hlr_gt=880150159800
   * gw_gt=880150159935
   * hlr_ssn=6
   * gw_ssn=147
   * app_url="http://127.0.0.1/ussd/mo.php"
   */
  memset(cbuf, 0, sizeof(cbuf));
  while (fgets(cbuf, sizeof(cbuf)-1, cfgfp)) {
    cbuflen = strlen(cbuf);
    if (cbuf[cbuflen-1] == '\n') {
      cbuf[--cbuflen] = '\0';
    }
    if (cbuf[cbuflen-1] == '\r') {
      cbuf[--cbuflen] = '\0';
    }


    ret = sscanf(cbuf, "%s = %s", ckey, cval);
    if (ret < 2) {
      fprintf(stderr, "Less than two items scanned\n");
      continue;
    }
    fprintf(stderr, "cbuf=%s, ckey=%s, cval=%s\n", cbuf, ckey, cval);

    if (strchr(ckey, '#') || strchr(cval, '#')) continue;

    coffset = 0;
    cptr = cval;
    if ((cptr = strchr(cptr, '"'))) {
      coffset = 1;
      cptr = cval + coffset;
      if ((cptr = strrchr(cptr, '"'))) {
	*cptr = '\0';
      }
    }

    cptr = cval + coffset;

    if (strcmp(ckey, "msc_ip") == 0) {
      strcpy(servaddr_str, cptr);
    } else if (strcmp(ckey, "msc_port") == 0) {
      servaddr_port = atoi(cptr);
    } else if (strcmp(ckey, "gw_ip") == 0) {
      strcpy(cliaddr_str, cptr);
    } else if (strcmp(ckey, "gw_port") == 0) {
      cliaddr_port = atoi(cptr);
    } else if (strcmp(ckey, "msc_pc") == 0) {
      msc_pc= (uint32_t) atoi(cptr);
    } else if (strcmp(ckey, "gw_pc") == 0) {
      ugw_pc= atoi(cptr);
    } else if (strcmp(ckey, "gw_pc") == 0) {
      ugw_pc= atoi(cptr);
    } else if (strcmp(ckey, "hlr_gt") == 0) {
      strcpy(hlr_gt, cptr);
    } else if (strcmp(ckey, "gw_gt") == 0) {
      strcpy(ugw_gt, cptr);
    } else if (strcmp(ckey, "hlr_ssn") == 0) {
      hlr_ssn = (uint8_t) atoi(cptr);
    } else if (strcmp(ckey, "gw_ssn") == 0) {
      ugw_ssn = (uint8_t) atoi(cptr);
    } else if (strcmp(ckey, "app_url") == 0) {
      strcpy(appurl, cptr);
    }

    fprintf(stderr, "ckey=<%s>, cptr=<%s>\n", ckey, cptr);
  }

  fclose(cfgfp);

err_ret:

  return 0;
}
