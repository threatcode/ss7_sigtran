/*
 * utils-test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int main(void)
{
  const char *str = "Hello%20World+Ayub";
  size_t len = 0;
  char *unescaped = rawurldecode(str, strlen(str), &len);

  if (unescaped) {
    fprintf(stderr, "Original String: [%s] (%lu)\nUnescaped String: [%s] (%lu)\n", str, strlen(str), unescaped, strlen(unescaped));
    free(unescaped);
  }

  return 0;
}
