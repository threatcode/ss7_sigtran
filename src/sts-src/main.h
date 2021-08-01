/*
 * main.h
 */
#ifndef __MAIN_H__
#define __MAIN_H__

#define _GNU_SOURCE

#include <stdio.h>
#ifndef DMALLOC
#include <string.h>
#endif
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <time.h>		/* nanosleep(2), etc. */
#include <setjmp.h>
#include <dlfcn.h>
#include "poll.h"
#include "lfq.h"		/* lock free queue (thread-safe for one producer and one consumer) */

#include "defs.h"		/* macro definitions */

#define err_exit(msg) \
  do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define err_warn(msg) perror(msg)

#define USLEEP(x) do { \
  struct timespec __ts__; \
  __ts__.tv_sec = x / 1000; \
  __ts__.tv_nsec = (x % 1000) * 1000; \
  nanosleep(&__ts__, NULL); \
} while (0)

typedef jmp_buf state_t;
#define state_new() MYCALLOC(1, sizeof(state_t))
#define state_save(state) setjmp(state)
#define state_restore(state) longjmp(state,1)


#ifndef CHECKFLAG
#define CHECKFLAG(x,y) ((x) & (y))
#endif
#ifndef SETFLAGS
#define SETFLAGS(fd,flags) fcntl((fd), F_SETFL, fcntl((fd), F_GETFL, 0) | (flags))
#endif
#ifndef SETNONBLOCKING
#define SETNONBLOCKING(fd) SETFLAGS(fd, O_NONBLOCK)
#endif

/* sleep time in usec */
#ifndef SLEEPTIME
#define SLEEPTIME	100
#endif
#ifndef MAXSLEEPTIME
#define MAXSLEEPTIME	1000000
#endif

#ifndef NWORKERS
#define NWORKERS 2
#endif

#ifndef MAXEVENTS
#define MAXEVENTS 1024
#endif

#ifdef __linux__
#define ACCEPT(sfd,addr,len) accept4((sfd),(addr),(len), SOCK_NONBLOCK | SOCK_CLOEXEC)
#else
#define ACCEPT(sfd,addr,len) accept((sfd),(addr),(len))
#endif

#if 0
long bytes_on_socket(int socket)
{
  size_t nbytes = 0;
  if ( ioctl(fd, FIONREAD, (char*)&nbytes) < 0 )  {
    fprintf(stderr, "%s - failed to get byte count on socket.\n", __func__);
    syslog(LOG_ERR, " %s - failed to get byte count on socket.\n", __func__);
    return -1;
  }
  return( (long)nbytes );
}
#endif

/*
 * ready() and process() __MUST_NOT__ block and should be fast
 * one worker will be blocked in their execution
 */
typedef enum { false, true } bool;
typedef struct {
  int fd;
  void *(*ready)(void *self, void *sys); /* (hook_t *, system_t *) */
  void *(*process)(void *self, void *sys);
  void *data; /* user data (session, etc.), modules will use it extensively for protocol-dependent way */
  event_t ev; /* event specification */
} hook_t;

#define hook_new() MYCALLOC(1, sizeof(hook_t))
#define hook_set_func(hp,_func) do { (hp)->ready = _func; } while (0)

typedef struct {
  int eventfd; /* main asynchronous event descriptor */
  struct lfq **q; /* workers' queue (queue per worker) */
  struct lfq **fq; /* free queue (queue per worker) */
  int nworkers; /* number of worker threads */
  event_t *events; /* list of events */
  sem_t *sem;
  int maxevents; /* maximum number of events to be fetched in one call */
  int nmodules; /* number of modules configured for loading */
  void *sigtran; /* FIXME: hack, for getting pointer to sigtran_t */
  uint8_t __trace_enabled__;
} system_t;

/* parameter to be passed to worker threads upon creation */
struct winfo {
  system_t *sys;
  int workernum;
};


system_t *ayubd_init(int nworkers, int maxevents);
int ayubd_config_read(system_t *sys);
int ayubd_module_load(system_t *sys, char *mod_name);
int ayubd_run(system_t *sys);
void ayubd_quit(system_t *sys);
void *ayubd_worker(void *arg); /* worker thread entry point */

#endif
