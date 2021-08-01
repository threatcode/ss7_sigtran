#include <stdio.h>
#include "http11_requests.h"

//#define WARN_IF(EXP) fprintf(stderr, "Warning: " #EXP "\n");

int main(void)
{
  char hbuf[512];
  int ret = 0;

  memset(hbuf, 0, sizeof(hbuf));
  ret = snprintf(hbuf, sizeof(hbuf)-1, "hello %s world", "ayub");
  fprintf(stderr, "ret = %d, buf=%s\n", ret, hbuf);

//  WARN_IF(Accept);
//  fprintf(stderr, "%d\n", HR_HOST);

  return 0;
}
