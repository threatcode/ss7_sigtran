/*
 * llist.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llist.h"
#include "defs.h"

/* list utility functions */
llist_t *llist_add(llist_t *list, void *ptr)
{
  llist_t *tmp = list;
  if (!ptr) return NULL;
  lnode_t *node = MYCALLOC(1, sizeof(lnode_t));
  node->data = ptr;
  node->next = NULL;
  if (!list) {
    list = node;
    return list;
  }

  while (tmp && tmp->next) {
    tmp = tmp->next;
  }
  tmp->next = node;

  return list;
}

void llist_free(llist_t *list, free_func_t free_func)
{
  if (!list) return;
  llist_t *tmp;

  while (list) {
    tmp = list;
    list = tmp->next;

    if (free_func) free_func(tmp->data);
    MYFREE(tmp);
  }
}

void llist_print(llist_t *list)
{
  while (list) {
    fprintf(stderr, "%s\n", (char *) list->data);
    list = list->next;
  }
}

void llist_print_func(llist_t *list, print_func_t print_func)
{
  while (list) {
    if (print_func) print_func(list->data);
    //fprintf(stderr, "%s\n", (char *) list->data);
    list = list->next;
  }
}
