/*
 * llist-test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llist.h"

int main(void)
{
  char *str;
  llist_t *list = NULL;

  str = strdup("Hello");
  list = llist_add(list, str);
  str = strdup("World");
  list = llist_add(list, str);

  llist_print(list);
  llist_free(list, free);

  return 0;
}
