/*
 * t_mtrace.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <mcheck.h>
#include <pthread.h>

void *tfunc(void *arg)
{
  malloc(500);

  pthread_exit(NULL);

  return NULL;
}

int main(int argc, char *argv[])
{
  int j;

  mtrace();

  for (j = 0; j < 2; j++)
    malloc(100);            /* Never freed--a memory leak */

  calloc(16, 16);             /* Never freed--a memory leak */

  pthread_t tid;
  pthread_create(&tid, NULL, tfunc, NULL);

  pthread_join(tid, NULL);

  exit(EXIT_SUCCESS);

  return 0;
}
