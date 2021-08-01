/*
 * mod_sigtran.h
 * keep-alive keeps keep-alive enabled clients happy and performs well too
 */
#ifndef __MOD_SIGTRAN_H__
#define __MOD_SIGTRAN_H__

#define _GNU_SOURCE

#ifndef DMALLOC
#include <string.h>
#endif
#include <stdlib.h>
#include <time.h>		/* time_t, time(2), etc. */
#include <sys/uio.h>		/* writev(2), struct iovec, etc. */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/timerfd.h>
#if 0
#include "../../main.h"
#endif

#include "m3ua.h"
#include "sccp.h"
#if 0
#include "crc.h"
#endif
#include <pthread.h>
#include <semaphore.h>
#include "ANY.h"

#include "tcap.h"

#include "iarray.h"


#include "module.h"

/* M3UA (SCTP) PORT */
#ifndef SIGTRAN_PORT
#define SIGTRAN_PORT 2905
#endif


typedef struct {
  struct sockaddr_in paddr; /* peer address */
} sigtran_sctp_info_t;

#ifndef MAXBUFSIZ
#define MAXBUFSIZ	4096
#endif


typedef struct sigtran sigtran_t;

typedef struct {
  struct lfq **mq;
  size_t nmq;
  sem_t *sem;
  //uint16_t *last_dialogue;
  iarray_t **dialogues;
  sigtran_t *st;
  struct lfq **fq; /* free queue for dialogue ids to be released (tcap worker will do it when resolving MAP ID) */

  pthread_rwlock_t *rwlocks; /* rwlocks for keeping the iarray safe */
} map_t;

typedef struct {
  struct lfq *q_to_tcap; /* send to tcap layer for processing */
  struct lfq *q_fr_tcap; /* receive from tcap layer for sending back to network */
  struct lfq *dfq; /* Dialogue Free Queue */
  int efd; /* eventfd */
  sem_t lock;
  map_t *map;
  uint16_t nmaps; /* how many MAP stacks running */
  uint32_t nextid; /* incremental variable */
  pthread_mutex_t mutex; /* mutex to prevent multiple MAP stacks to write to sigtran socket */
} sigtran_tcap_t;

struct sigtran {
  system_t *sys;
  int fd; /* receiving M3UA socket */
  int cfd; /* service client socket */
  int tfd; /* timer descriptor (future) */
  int32_t m3ua_hb; /* m3ua ASPSM heartbeat (will quit if greater than 5) */
//  octet buffer[MAXBUFSIZ];
//  uint32_t bufpos;
  m3ua_t *sm; /* source m3ua */

  struct sockaddr_in servaddr;
  socklen_t addrlen;
  uint32_t ugw_pc; /* ussd gw point code */
  uint32_t msc_pc; /* msc point code */
  uint8_t ugw_ssn; /* ussd gw ssn (147) */
  uint8_t hlr_ssn; /* hlr ssn (6) */
  char ugw_gt[20];
  char hlr_gt[20];

  char appurl[512]; /* base url for 3rd party ussd application */
  //size_t app_url_timeout; /* default 60 */
  //char app_url_error_msg[256]; /* Error message to be sent to MS in case of unreachability of application or timeout */

  sigtran_tcap_t tcap; /* persistent tcap information */
  /* sctp stream information */
  uint32_t ppid; /* Payload Protocol ID */
  uint16_t mgmt_str_no;
  uint16_t data_str_no;
//  struct sctp_sndrcvinfo *sri; /* for future use (for load balancing on streams) */
};
extern sigtran_t *sigtran_ptr;
#define TTRACE(format, ...) do { if (sigtran_ptr->sys->__trace_enabled__) fprintf(stderr, format, ##__VA_ARGS__); } while (0)

#if 0
#define MAX_HEADERS 100		/* maximum number of headers allowed */
typedef struct {
  uint8_t keyidx;
  char *value;
} sigtran_header_t;
#endif

typedef hook_t sigtran_session_t;

void sigtran_state_machine(sigtran_t *s);

typedef struct {
  m3ua_protocol_data_t *pdata; /* m3ua protocol data packet (parsed) */
  sccp_data_udt_t *udt;
  m3ua_t *m3ua;
//  time_t heartbeat;

  /* misc members */
  sigtran_t *st;
  void *tcm; /* TCMessage_t * */
  void *tcsess; /* tcap_session_t * */
  void *comp; /* Component_t * */
  void *param; /* Parameter_t * */
  void *usessinfo; /* ussd_session_t * */

} sigtran_tcap_info_t;

#define sigtran_session_new(hs,sys,fd) do {			\
  hs = lfq_dequeue((sys)->fq[fd%(sys)->nworkers]);		\
  if (!hs) hs = hook_new();					\
} while (0)

#if 0
#define sigtran_session_new() hook_new()
#endif
#define sigtran_session_free(s,sys) do {				\
  if (s) {							\
    int x = (s)->fd % (sys)->nworkers;				\
    (s)->fd = 0;						\
    (s)->ready = NULL;						\
    (s)->process = NULL;					\
    lfq_enqueue(((system_t *) (sys))->fq[x], (s));		\
  }								\
} while (0)

#define sigtran_session_close(s,sys) do {				\
  close((s)->fd);						\
  sigtran_session_free(s,sys);					\
} while (0)


#if 0
static void sigtran_elem_cb(void *data, const char *at, size_t len)
{
  DUMP(at,len);
  return;
}
#endif


#define DUMP(at,len) do { fprintf(stderr, "%s\n", __func__); write(STDERR_FILENO, at, len); write(STDERR_FILENO, "\n", 1); } while (0)
#define DUMPX(field,flen,value,vlen) do { fprintf(stderr, "%s\n", __func__); write(STDERR_FILENO, field, flen); write(STDERR_FILENO, "\n", 1); write(STDERR_FILENO, value, vlen); write(STDERR_FILENO, "\n", 1); } while (0)

typedef struct {
  char *rname;
  void (*cb)(char *field, size_t flen);
} sigtran_req_t;

void *sigtran_tcap_worker(void *st);
void sigtran_tcap_info_free(sigtran_tcap_info_t *sinfo);


#endif /* !__MOD_SIGTRAN_H__ */
