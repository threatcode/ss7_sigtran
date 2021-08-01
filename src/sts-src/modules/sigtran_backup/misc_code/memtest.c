#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
  int n = 1000 * 1000;

  getchar();
  char *x = malloc(n);
  memset(x, '0', n-1);
  x[n-1] = '\0';

  getchar();

  return 0;
}
