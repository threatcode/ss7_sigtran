#ifndef _DUMP_FUNCS_C_
#define _DUMP_FUNCS_C_

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

#include <stdio.h>
#include <ctype.h>

void hexdump(void *mem, unsigned int len)
{
  unsigned int i, j;

  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
  {
    /* print offset */
    if(i % HEXDUMP_COLS == 0)
    {
      printf("0x%06x: ", i);
    }

    /* print hex data */
    if(i < len)
    {
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    }
    else /* end of block, just aligning for ASCII dump */
    {
      printf("   ");
    }

    /* print ASCII dump */
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
    {
      for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
      {
	if(j >= len) /* end of block, not really printing */
	{
	  putchar(' ');
	}
	else if(isprint(((char*)mem)[j])) /* printable char */
	{
	  putchar(0xFF & ((char*)mem)[j]);        
	}
	else /* other char */
	{
	  putchar('.');
	}
      }
      putchar('\n');
    }
  }
}

octet *hex2bin(octet *hex, uint16_t len)
{
  octet *ret;
  uint16_t count = 0;
  if (len % 2 != 0) return NULL; /* not even number of hex chars */

  len = len / 2;
  ret = calloc(1, len);

  for (count = 0; count < len; count++) {
    sscanf((char *) hex, "%2hhx", &ret[count]);
    hex += 2;
  }

  return ret;
}




#endif
