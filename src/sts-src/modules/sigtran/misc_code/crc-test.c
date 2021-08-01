/**********************************************************************
 *
 * Filename:    main.c
 * 
 * Description: A simple test program for the CRC implementations.
 *
 * Notes:       To test a different CRC standard, modify crc.h.
 *
 * 
 * Copyright (c) 2000 by Michael Barr.  This software is placed into
 * the public domain and may be used for any purpose.  However, this
 * notice must not be changed or removed and no warranty is either
 * expressed or implied by its publication or distribution.
 **********************************************************************/

#include <stdio.h>
#include <string.h>

#include "crc.h"


int
main(void)
{
  uint8_t test[] = "123456789";
  char *msg = (char *) test;


  /*
   * Print the check value for the selected CRC algorithm.
   */
  printf("The check value for the %s standard is 0x%X\n", CRC_NAME, CHECK_VALUE);

  /*
   * Compute the CRC of the test message, slowly.
   */
  printf("The crc_slow() of \"123456789\" is 0x%X\n", crc_slow(test, strlen(msg)));

  /*
   * Compute the CRC of the test message, more efficiently.
   */
  crc_init();
  printf("The crc_fast() of \"123456789\" is 0x%X\n", crc_fast(test, strlen(msg)));

  return 0;
}   /* main() */
