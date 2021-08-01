/*
 * lfq-list-test.c
 * lfq testing if there is problems with the queue in multithreaded programs
 */
#include <stdio.h>
#include <pthread.h>
#include "lfq.h"

#ifndef NWORKERS
#define NWORKERS 4
#endif

struct lfq *q[NWORKERS];

void *worker(void *arg)
{
  int i, x;
  x = (int) arg;
  while (1) {
    i = (int) lfq_dequeue(q[x]);
    if (i == 0) {
      /*
      fprintf(stderr, "worker[%d]: no data. going to sleep...\n", x);
      */
      usleep(10000);
    }
  }

  pthread_exit(NULL);
}

int main(int argc, char **argv)
{
  pthread_t tid[NWORKERS];
  register int i;

  for (i = 0; i < NWORKERS; ++i) {
    q[i] = lfq_new();
    pthread_create(&tid[i], NULL, worker, (void *) i);
  }

  i = 0;
  while (1) {
    lfq_enqueue(q[i%NWORKERS], (void *) i);
    ++i;
  }

  return 0;
}
