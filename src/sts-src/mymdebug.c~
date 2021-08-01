/*
 * mymdebug.c
 */
#include "mymdebug.h"
#include <stdio.h>

#if 0
/* TCMALLOC */
/* TCMALLOC will be loaded with LD_PRELOAD command. Because liblfds and others
 * will allocate using system's malloc. So, to use tcmalloc for all I will use
 * LD_PRELOAD method.
 * Also to consume less memory I will use the libtcmalloc_minimal.so and strip
 * it.
 */
#include <google/tcmalloc.h>
#endif

/*
 * Hook variables are not thread-safe so they are deprecated now.
 * Programmers should instead preempt calls to the relevant functions
 * by defining and exporting functions like "malloc" and "free".
 */

void *mymalloc_debug(size_t size)
{
  void *p = malloc(size);
  MTRACE("+%p", p);
  return p;
}

void *mycalloc_debug(size_t nmemb, size_t size)
{
  void *p = calloc(nmemb, size);
  MTRACE("+%p", p);
  return p;
}

void *myrealloc_debug(void *ptr, size_t size)
{
  void *p = realloc(ptr, size);
  if (p != ptr) { /* memory address changed, so previous one freed internally */
    MTRACE("-%p", ptr);
  }
  MTRACE("+%p", p);
  return p;
}

void myfree_debug(void *ptr)
{
  MTRACE("-%p", ptr);
  free(ptr);
}

char *mystrdup_debug(const char *str)
{
  char *p = strdup(str);
  MTRACE("+%p", p);
  return p;
}




#if 0

void *mymalloc_debug_line(size_t size, const char *func, const char *file, size_t line)
{
  void *p = malloc(size);
  MTRACE("+%p", p);
  return p;
}

void *mycalloc_debug_line(size_t nmemb, size_t size, const char *func, const char *file, size_t line)
{
  void *p = calloc(nmemb, size);
  MTRACE("+%p", p);
  return p;
}

void *myrealloc_debug_line(void *ptr, size_t size, const char *func, const char *file, size_t line)
{
  void *p = realloc(ptr, size);
  if (p != ptr) { /* memory address changed, so previous one freed internally */
    MTRACE("-%p", ptr);
  }
  MTRACE("+%p", p);
  return p;
}

void myfree_debug_line(void *ptr, const char *func, const char *file, size_t line)
{
  MTRACE("-%p", ptr);
  free(ptr);
}
#endif
