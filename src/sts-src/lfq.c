/*
 * lfq.c
 * lock-free queue
 * safe for one producer, one consumer
 * Idea from Dr. Dobb's Journal
 */
#include "lfq.h"
#include "mymdebug.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned char uint8_t;

struct node *lfq_node_new(void *value)
{
  struct node *node = MYMALLOC(sizeof(struct node));
  node->value = value;
  node->next = NULL;

  return node;
}

void lfq_node_delete(struct node *node)
{
  MYFREE(node);
}

struct lfq *lfq_new(void)
{
  struct lfq *q = MYMALLOC(sizeof(struct lfq));
  struct node *node = lfq_node_new(NULL);
  q->first = q->divider = q->last = node;

  return q;
}

void lfq_delete(struct lfq *q)
{
  struct node *tmp = NULL;
  while (q->first != NULL) {
    tmp = q->first;
    q->first = tmp->next;
    MYFREE(tmp);
  }

  MYFREE(q);
}

void lfq_enqueue(struct lfq *q, void *value)
{
  struct node *tmp = NULL;
  if (!q) return;

  q->last->next = lfq_node_new(value); /* add the new item */
  q->last = q->last->next; /* publish it */

  while (q->first != q->divider) { /* trim unused nodes */
    tmp = q->first;
    q->first = q->first->next;
    MYFREE(tmp);
  }
}

/*
 * dequeue doesn't remove the node from Q
 * it just advances the divider
 */
void *lfq_dequeue(struct lfq *q)
{
  void *result = NULL;
  if (q->divider != q->last) {
    result = q->divider->next->value;
    q->divider = q->divider->next;
    return result;
  }
  return NULL;
}

int lfq_is_empty(struct lfq *q)
{
  return (q->divider == q->last);
}

void lfq_push(struct lfq *q, void *value)
{
  q->last->next = lfq_node_new(value); /* add the new item */
  q->last = q->last->next; /* publish it */
}

/*
 * fetch a node from the queue and advance the divider
 */
void *lfq_fetch(struct lfq *q, struct node **divider)
{
  void *result = NULL;
  if (q->divider != q->last) {
    if (*divider == NULL) *divider = q->divider;
    result = (*divider)->next->value;
    *divider = (*divider)->next;
    return result;
  }
  return NULL;
}

