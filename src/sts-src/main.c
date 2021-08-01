/*
 * main.c
 */
#include "main.h"
#include "module.h"
//#include <curl/curl.h>


int main(int argc, char **argv)
{
  system_t *sys = ayubd_init(NWORKERS, MAXEVENTS);
  assert(sys != NULL);
  assert(ayubd_config_read(sys) == 0);
  return ayubd_run(sys);
}

int ayubd_config_read(system_t *sys)
{
  sys->nmodules = 0; /* number of modules loaded (will be updated by ayubd_module_load() */
  assert(ayubd_module_load(sys, "sigtran") == 0);
  assert(ayubd_module_load(sys, "http") == 0);

  return 0;
}

int ayubd_module_load(system_t *sys, char *mod_name)
{
#if 0
  module_start(sys);
#endif
  int ret = -1;
  char *error = NULL;
  int (*mod_start)(system_t *);
  char sopath[256] = { 0 };

  fprintf(stderr, "Going to load module: %s\n", mod_name);
  module_t *mod = module_new();
  //strncpy(mod->name, mod_name, sizeof(mod_name));
  strcpy(mod->name, mod_name);
  snprintf(sopath, sizeof(sopath)-1, "modules/%s/mod_%s.so", mod->name, mod_name);
  mod->handle = dlopen(sopath, RTLD_LAZY);
  if (!mod->handle) {
    DTRACE("Module load failure [%s], %s.\n", mod_name, dlerror());
    return ret;
  }

  dlerror(); /* clear any existing error */

  mod_start = dlsym(mod->handle, "module_start");
  if ((error = dlerror()) != NULL) {
#if 0
    DEBUG(stderr, "dlsym returned error for function module_start. [%s]\n", error);
#endif
    dlclose(mod->handle);
    return ret;
  }

  mod->fd = (*mod_start)(sys); /* invoke the module start function */

  sys->nmodules++; /* number of modules configured to load */
  if (mod->fd >= 0) ret = 0;
  /*
  mod_http_init(sys);
  if (mod_name == NULL) {
  } else {
    if (mod_name[0] != '\0') {
      mod_http_init(sys);
    }
  }
  */
  MYFREE(mod);

  return ret;
}

system_t *ayubd_init(int nworkers, int maxevents)
{
  register int i = 0;
  struct winfo *wi = NULL;
  pthread_t tid = 0;
#if 0
  pthread_attr_t attr;
#endif
  system_t *sys = NULL;

#if 0
  long curl_flags = 0; 
#ifdef USE_CURL_SSL
  curl_flags = CURL_GLOBAL_ALL;
#else
  curl_flags = CURL_GLOBAL_NOTHING;
#endif

  if (

#if 0
      /* this doesn't work */
      curl_global_init_mem(curl_flags, MYMALLOC, MYFREE, MYREALLOC, MYSTRDUP, MYCALLOC)
#else
      curl_global_init(curl_flags)
#endif
      != 0)
  {
    CRITICAL("cURL subsystem failed to initialize. Exiting.\n");
    exit(EXIT_FAILURE);
  }
#endif

  /*
  DEBUG(stderr, "Going to initialize system with %d workers and %d events\n",
      nworkers, maxevents);
      */
  sys = MYCALLOC(1, sizeof(system_t));
  assert(ayubd_module_load(sys, "license") == 0);
  sys->eventfd = EVQ_CREATE(); /* create event queue (kqueue/epoll) */
  sys->nworkers = nworkers;
  sys->maxevents = maxevents;
  sys->q = (struct lfq **) MYCALLOC(sys->nworkers, sizeof(struct lfq));
  sys->fq = (struct lfq **) MYCALLOC(sys->nworkers, sizeof(struct lfq));
  sys->sem = MYCALLOC(sys->nworkers, sizeof(sem_t));
  wi = (struct winfo *) MYCALLOC(sys->nworkers, sizeof(struct winfo));
#if 0
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif
  /* this must be called before creating child threads */
  /* has been called from ayubd_init() to call before creating threads, so that child threads have the same signal handlers */
  assert(ayubd_module_load(sys, "signal") == 0);
  for (i = 0; i < sys->nworkers; ++i) {
    wi[i].sys = sys;
    wi[i].workernum = i;

    sys->q[i] = lfq_new();
    sys->fq[i] = lfq_new();
    sem_init(&sys->sem[i], 0, 0);
    //pthread_create(&tid, &attr, ayubd_worker, (void *) &wi[i]);
    pthread_create(&tid, NULL, ayubd_worker, (void *) &wi[i]);
    pthread_detach(tid);
  }

#if 0
  pthread_attr_destroy(&attr);
#endif

  return sys;
}

int ayubd_run(system_t *sys)
{
  int nfds = 0;
  register int n = 0;
  int x = 0;

  sys->events = (event_t *) MYCALLOC(sys->maxevents, sizeof(event_t));
  if (sys->events == NULL) {
    err_exit("MYCALLOC: MAXEVENTS * event_t");
  }
  event_t ev;
  hook_t *hp;

  fprintf(stderr, "Running event loop\n");

#if 0
  register int isempty = 0;
#endif
  while (1) {
#if 0
    USLEEP(SLEEPTIME); /* this sleep makes us call less epoll_wait() and returns more descriptors at once */
    DEBUG(stderr, "Polling indefinitely for events...\n");
#endif
    nfds = EVQ_POLL(sys->eventfd, sys->events, sys->maxevents);
    if (nfds == -1) {
      err_warn("EVQ_POLL");
      continue;
    }
    for (n = 0; n < nfds; ++n) {
      ev = sys->events[n];
      hp = ev.data.ptr;
      hp->ev.events = ev.events; /* update the event flags */
      /* invoke hook functions in here */
      if (hp && hp->ready) { /* ready should return NULL when something special other than that require processing */
	if (hp->ready(hp, sys)) {
	  x = hp->fd % sys->nworkers;
#if 0
	  isempty = lfq_is_empty(sys->q[x]);
#endif
	  lfq_enqueue(sys->q[x], hp);
#if 0
	  if (isempty) { /* someone is waiting on the semaphore */
#endif
	    sem_post(&sys->sem[x]);
#if 0
	  }
#endif
	}
      }
    }
  }
  return 0;
}

void ayubd_quit(system_t *sys)
{
  if (sys) {
    if (sys->q) MYFREE(sys->q);
    MYFREE(sys);
  }
}

void *ayubd_worker(void *arg)
{
  system_t *sys = NULL;
  int x = 0;
#if 0
  int sleeptime = SLEEPTIME;
#endif
  hook_t *s = NULL;
  struct winfo *wi = (struct winfo *) arg;
  sys = wi->sys;
  x = wi->workernum;

  while (1) {
    sem_wait(&sys->sem[x]);
    s = lfq_dequeue(sys->q[x]); /* dequeue if any, from own queue */
    if (s == NULL) { /* nothing much yet */
      /*
      USLEEP(sleeptime);
      if (sleeptime < MAXSLEEPTIME) sleeptime += SLEEPTIME;
      */
      /* no events in queue */
      continue;
    }
#if 0
    else {
      sleeptime = SLEEPTIME; /* reset sleeptime */
    }
#endif

    /* now process the event */
    if (s->process) s->process(s, sys);
    /*
    http_process_data(s);
    */
  }

  pthread_exit(NULL);
  return NULL;
}
