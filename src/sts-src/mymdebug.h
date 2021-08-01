/*
 * mymdebug.h
 */
#ifndef _MYMDEBUG_H_
#define _MYMDEBUG_H_

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#undef  MYMALLOC
#undef  MYCALLOC
#undef  MYREALLOC
#undef  MYFREE
#undef  MYSTRDUP


#ifdef MYMDEBUG
//#define MTRACE(format, ...) fprintf(stderr, "[%-20s:%4lu] %-30s: " format, file, line, func, ##__VA_ARGS__)
//#define MTRACE(format, ...) fprintf(stderr, format "|[%s:%lu]:%s\n", ##__VA_ARGS__, file, line, func)
#define MTRACE(format, ...) fprintf(stderr, format "|[%s:%d]:%s\n", ##__VA_ARGS__, __FILE__, __LINE__, __func__)
#define MYMALLOC	mymalloc_debug
#define MYCALLOC	mycalloc_debug
#define MYREALLOC	myrealloc_debug
#define MYFREE		myfree_debug
#define MYSTRDUP	mystrdup_debug
void *mymalloc_debug(size_t size);
void *mycalloc_debug(size_t nmemb, size_t size);
void *myrealloc_debug(void *ptr, size_t size);
void myfree_debug(void *ptr);
char *mystrdup_debug(const char *str);

#else		/* !MYMDEBUG */
#define MTRACE(format, ...)


#ifdef  TCMALLOC
#include <google/tcmalloc.h>
#define MYMALLOC		tc_malloc
#define MYCALLOC		tc_calloc
#define MYREALLOC		tc_realloc
#define MYFREE			tc_free
#define MYSTRDUP		strdup
#else
#define MYMALLOC		malloc
#define MYCALLOC		calloc
#define MYREALLOC		realloc
#define MYFREE			free
#define MYSTRDUP		strdup
#endif
#endif

#endif
