/*
 * llist.h
 */
#ifndef _LLIST_H_
#define _LLIST_H_


struct lnode {
  void *data;
  struct lnode *next;
};
typedef struct lnode lnode_t;
typedef struct lnode llist_t;

typedef void (*free_func_t)(void *);
typedef void (*print_func_t)(void *);

llist_t *llist_add(llist_t *list, void *data);
llist_t *llist_del(llist_t *list,  lnode_t *node);
void llist_free(llist_t *list, free_func_t free_func);
void llist_print(llist_t *list);
void llist_print_func(llist_t *list, print_func_t print_func);


#endif
