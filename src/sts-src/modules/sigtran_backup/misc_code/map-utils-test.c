/*
 * map-utils-test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "map-utils.h"

int main(void)
{
  const char *msg = "Hello Ayub";
  const char *msisdn = "8801558140873";

  USSD_Arg_t *uinfo = map_build_ussd_arg(msg, msisdn);
  map_free_ussd_arg(uinfo);

  return 0;
}
