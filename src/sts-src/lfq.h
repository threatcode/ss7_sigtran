/*
 * lfq.h
 * Lock-Free Queue Implementation (single producer, single consumer)
 */
#ifndef __LFQ_H__
#define __LFQ_H__


struct node {
  void *value;
  struct node *next;
};

struct lfq {
  struct node *first; /* for producer only */
#if 0
  volatile struct node *divider, *last; /* shared */
#endif
  struct node *divider, *last; /* shared */
};

struct node *lfq_node_new(void *value);
void lfq_node_delete(struct node *node);
struct lfq *lfq_new(void);
void lfq_enqueue(struct lfq *q, void *value);
void lfq_push(struct lfq *q, void *value); /* list version */
void *lfq_dequeue(struct lfq *q);
void *lfq_fetch(struct lfq *q, struct node **divider); /* list version */
void lfq_delete(struct lfq *q);
int lfq_is_empty(struct lfq *q);

#endif
