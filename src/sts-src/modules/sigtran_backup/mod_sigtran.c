/*
 * mod_sigtran.c
 * sigtran module (over sctp/ip)
 * Author: Ayub <ayub@nixtecsys.com>
 */
#include "utils.h"
#include "fcntl.h"
#if 0
#include "crc.h"
#endif
#include <signal.h>
#include <errno.h>
#include <sys/eventfd.h>

#ifdef MTRACE
#include <mcheck.h>
#endif

#ifdef TIMETRACE
#include <sys/time.h>
suseconds_t get_usecs(void)
{
  struct timeval tv;
  suseconds_t usecs = 0;
  memset(&tv, 0, sizeof(tv));
  if (gettimeofday(&tv, NULL) == 0) {
    usecs = tv.tv_sec * 1000000 + tv.tv_usec;
  }
  return usecs;
}
#define USECDUMPR() fprintf(stderr, "Receiving Usec >>> %lu <<<\n", get_usecs())
#define USECDUMPS() fprintf(stderr, "Sending Usec >>> %lu <<<\n", get_usecs())
#else
#define USECDUMPR()
#define USECDUMPS()
#endif

#include "mod_sigtran.h"
//#include "url-utils.h"

//#include <gperftools/heap-profiler.h>


#if 0
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#if 0
#include <libtcap.h>
#endif


#if 0
static char obuf[256];
static out_t out;
#endif

#define MAX_OSTREAM 2
#define MAX_ISTREAM 2
#define MAX_ATTEMPTS 2

static void sigtran_state_mgmt(sigtran_t *s);
static void sigtran_state_tm(sigtran_t *s);
static void sigtran_state_ssnm(sigtran_t *s);
static void sigtran_state_aspsm(sigtran_t *s);
static void sigtran_state_asptm(sigtran_t *s);
static void sigtran_state_rkm(sigtran_t *s);
static void sigtran_sccp_udt(sigtran_t *s, m3ua_protocol_data_t *md);
static void sigtran_tcap_init(sigtran_t *st);

static void *sigtran_recv_from_tcap(void *s, void *sys);
sigtran_t *sigtran_ptr = NULL;



#if 0
typedef hook_t sigtran_http_session_t;

/* state machine should be developed from received packets */
static void *http_process(void *s, void *sys)
{
  //sigtran_http_session_t *ss = (sigtran_http_session_t *) s;
  DTRACE("HTTP Data to be processed\n");

  return NULL;
}

static void *http_ready(void *self, void *sys)
{
  void *ret = NULL;
  sigtran_http_session_t *s = self;
  if (CHECKFLAG(s->ev.events, EPOLLRDHUP) ||
      CHECKFLAG(s->ev.events, EPOLLHUP) ||
      CHECKFLAG(s->ev.events, EPOLLERR)
     ) {
    DTRACE("HTTP socket got EPOLL{RDHUP|HUP|ERR}. Closing.\n");
    MYFREE(s);
    ret = NULL;
  } else {
    ret = s;
  }

  return ret;
}

void sigtran_http_event_add(sigtran_t *st, int fd, void *data)
{
  hook_t *s = hook_new();
  if (s) {
    s->fd = fd;
    s->data = data;

    *(&s->ready) = http_ready;
    *(&s->process) = http_process;
    s->ev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLET;
    s->ev.data.ptr = s;
  }
  system_t *sys = st->sys;
  EVQ_ADD(sys->eventfd, fd, &s->ev);
}



/* action must contain only the base url, excluding the query string part */
/* will make it more robust later */
/* key can't contain space or other illegal characters */
int sigtran_http_request_new(sigtran_t *st, char *addr, uint16_t port, const const char *action, llist_t *kvs)
{
#define HTTP_MAX_PACKET		4096
  int fd = tcp_connect(addr, port);
  if (fd <= 0) return -1;

  sigtran_http_event_add(st, fd, NULL);
  llist_t *tmp = kvs;
  kv_t *kvp = NULL;
  char http_req[HTTP_MAX_PACKET];
  int pos = 0; /* last position in http_req */
  char *ptr;
  size_t nextpos = 0;
  const char *method = "GET";

  memset(http_req, 0, sizeof(http_req));

  pos = strlen(method);
  strncpy(http_req, method, pos);
  http_req[pos++] = ' ';

  nextpos = strlen(action);
  strncpy(http_req+pos, action, nextpos);
  pos += nextpos;

  /* there is some query string */
  if (kvs) {
    http_req[pos++] = '?';
  }

  /*
  ptr = url_encode(action, strlen(action), &nextpos);
  pos = snprintf(http_req, sizeof(http_req)-1, "%s %s HTTP/1.0\r\n", method, action);
  MYFREE(ptr);
  */

  while (tmp) {
    kvp = tmp->data;
    strncpy(http_req+pos, kvp->key, kvp->key_len);
    pos += kvp->key_len;
    http_req[pos++] = '=';
    ptr = url_encode(kvp->val, kvp->val_len, &nextpos);
    strncpy(http_req+pos, ptr, nextpos);
    pos += nextpos;
    MYFREE(ptr);

    tmp = tmp->next;
  }

  const char *end = "HTTP/1.0\r\n\r\n";
  nextpos = strlen(end);
  strncpy(http_req+pos, end, nextpos);
  pos += nextpos;

  ssize_t nw = send(fd, http_req, pos, 0);
  if (nw != pos) {
    perror("send");
  }

  return fd;
}

#endif



#if 0
/* send full M3UA packet from file */
void sigtran_send_binary_from_file(sigtran_t *s, const char *filename);

void sigtran_send_binary_from_file(sigtran_t *s, const char *filename)
{
  FTRACE();

  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    perror("open");
    return;
  }
  off_t size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET); /* rewind the seek position */
  octet *buf = MYCALLOC(1, size);
  ssize_t nr = read(fd, buf, size);
  if (nr != size) {
    fprintf(stderr, "Attempted to read %u, got %u\n", (unsigned int) size, (unsigned int) nr);
    perror("read");
  } else {
    ssize_t nr = 0;
    if ((nr = sctp_sendmsg(s->fd, buf, size, (struct sockaddr *) &s->servaddr, s->addrlen, s->ppid, 0, s->data_str_no, 0, 0)) != size) {
      fprintf(stderr, "Less data written to socket, attempted %d bytes, written %d bytes\n", size, nr);
    }
  }

  MYFREE(buf);

  close(fd);
}
#endif

void sigtran_tcap_info_free(sigtran_tcap_info_t *sinfo)
{
  FTRACE();

  if (sinfo) {
    if (sinfo->pdata) { MYFREE(sinfo->pdata); sinfo->pdata = NULL; }
    if (sinfo->udt) { MYFREE(sinfo->udt); sinfo->udt = NULL; }
    if (sinfo->m3ua) { m3ua_free(sinfo->m3ua); sinfo->m3ua = NULL; }

    /* misc members */
    if (sinfo->tcm) { tcap_free(sinfo->tcm); sinfo->tcm = NULL; }
    //if (sinfo->tcsess) { MYFREE(sinfo->tcsess); sinfo->tcsess = NULL; } // will be freed by sigtran_tcap_resolve_map_id()
    //if (sinfo->comp) { MYFREE(sinfo->comp); sinfo->comp = NULL; } // not allocated by me
    //if (sinfo->param) { MYFREE(sinfo->param); sinfo->param = NULL; } // not allocated by me
    if (sinfo->usessinfo) { MYFREE(sinfo->usessinfo); sinfo->usessinfo = NULL; }
    MYFREE(sinfo);
  }
}

static void sigtran_sccp_udt(sigtran_t *s, m3ua_protocol_data_t *md)
{
  FTRACE();

  uint32_t nextpos = 0;
  sigtran_tcap_info_t *sinfo = MYCALLOC(1, sizeof(*sinfo));
  sinfo->st = s;
//  sinfo->heartbeat = time(NULL);

  sinfo->m3ua = m3ua_build(s->sm->head.mclass, s->sm->head.mtype, NULL); /* make a blank m3ua packet */

  sinfo->pdata = MYCALLOC(1, sizeof(m3ua_protocol_data_t));
  memcpy(sinfo->pdata, md, sizeof(m3ua_protocol_data_t));

  nextpos = 0;
  sinfo->udt = sccp_octet2udt(sinfo->pdata->data, sinfo->pdata->datalen, &nextpos);
  if (!sinfo->udt) goto err;

  m3ua_point_code_t tmpc;
  tmpc = sinfo->pdata->opc;
  sinfo->pdata->opc = sinfo->pdata->dpc; /* swap the point codes for return path */
  sinfo->pdata->dpc = tmpc;

  char calling_gt[15], called_gt[15];
  uint8_t np = 0;
  TTRACE(">>> sccp: calling=%s, called=%s\n",
      decode_called_party(sinfo->udt->calling.gt.digits, 6, calling_gt, &np),
      decode_called_party(sinfo->udt->called.gt.digits, 6, called_gt, &np)
      );

  /* swap called party with calling party address, to deliver reply message to user */
  sccp_called_party_address_t tmp;
  tmp = sinfo->udt->called;
  sinfo->udt->called = sinfo->udt->calling;
  sinfo->udt->calling = tmp;

  /* send to TCAP for processing */
  DTRACE("Sending sinfo to tcap for processing\n");
  lfq_enqueue(s->tcap.q_to_tcap, sinfo);
  sem_post(&s->tcap.lock); /* unlock the sigtran_tcap thread */

  //sccp_dump_udt(udt);

  //sigtran_tcap_process(s, udt->data, udt->data_len);

#if 0
  /* just to check if encoding and decoding works */
  octet *buf = NULL;
  /* checking if encoding and decoding works */
  buf = sccp_udt2octet(udt, &nextpos);
  MYFREE(udt);
  udt = sccp_octet2udt(buf, nextpos, &nextpos);
  if (udt) sccp_dump_udt(udt);
  MYFREE(buf);
#endif

  return;

err:
  sigtran_tcap_info_free(sinfo);

  return;
}


void sigtran_state_mgmt(sigtran_t *s)
{
  FTRACE();

  mytlv_t *t = NULL;
  llist_t *l = NULL;
  uint16_t stat_type = 0;
  uint16_t stat_info = 0;
  octet *buf = NULL;
  uint32_t nextpos = 0;
  ssize_t nr = 0;

  switch (s->sm->head.mtype) {
    case M3UA_MSG_TYPE_MGMT_NTFY:
      l = s->sm->tlvs;
      while (l) {
	t = (mytlv_t *) l->data;
	if (t && t->tag == 0x000d) { /* Status */
	  memcpy(&stat_type, &t->val[0], 2);
	  stat_type = ntohs(stat_type);
	  memcpy(&stat_info, &t->val[2], 2);
	  stat_info = ntohs(stat_info);
	  DTRACE("Status type: 0x%x\n", stat_type);
	  DTRACE("Status info: 0x%x\n", stat_info);
	  if (stat_type == 1) { /* AS-State_Change */
	    if (stat_info == 2) { /* AS-INACTIVE */
	      /* need to send ASPAC */
	      buf = m3ua_octet_ASPAC(&nextpos);
	      if (!buf) {
		CRITICAL("*** ASPAC packet not created\n");
	      } else {
		DTRACE("Sending ASPAC\n");
		if ((nr = sctp_sendmsg(s->fd, buf, nextpos, (struct sockaddr *) &s->servaddr, s->addrlen, s->ppid, 0, s->mgmt_str_no, 0, 0)) != nextpos) {
		  CRITICAL("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nr);
		}
		MYFREE(buf);
	      }
	    }
	    if (stat_info == 3) { /* AS-ACTIVE */
	      /* need to send DAVA */
	      buf = m3ua_octet_DAVA(s->ugw_pc, &nextpos);
	      if (!buf) {
		CRITICAL("*** DAVA packet not created\n");
	      } else {
		DTRACE("Sending DAVA\n");
		if ((nr = sctp_sendmsg(s->fd, buf, nextpos, (struct sockaddr *) &s->servaddr, s->addrlen, s->ppid, 0, s->mgmt_str_no, 0, 0)) != nextpos) {
		  CRITICAL("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nr);
		}
		MYFREE(buf);
	      }

	      /* Send ATI query */
	      //sigtran_send_binary_from_file(s, "/home/ayub/ayubd-ng/modules/sigtran/ati.m3ua.packet.bin");
	    }

	  }
	}
	l = l->next;
      }
      break;
    default:
      CRITICAL("[MGMT] mclass=0x%x (%u), mtype=0x%x (%u)\n",
	  s->sm->head.mclass, s->sm->head.mclass,
	  s->sm->head.mtype, s->sm->head.mtype);
      break;
  }
}




/* here goes real SCCP/TCAP/MAP analysis */
static void sigtran_state_tm(sigtran_t *s)
{
  FTRACE();
  mytlv_t *t = NULL;
  llist_t *l = NULL;
  m3ua_protocol_data_t *pdata = NULL;
  uint32_t nextpos = 0;
  uint8_t mtype = 0; /* type of sccp packet */


  if (!s || !s->sm) return;

  switch (s->sm->head.mtype) {
    case M3UA_MSG_TYPE_TM_DATA:
      l = s->sm->tlvs;
      while (l) {
	t = (mytlv_t *) l->data;
	if (t && t->tag == 0x0210) { /* Protocol Data */
	  pdata = m3ua_octet2pdata(t->val, t->len-4, &nextpos);
	  /*
	  m3ua_pdata_dump(pdata);
	  fprintf(stderr, "*** Checking encoding and decoding ***\n");
	  octet *buf = m3ua_pdata2octet(pdata, &nextpos);
	  if (pdata) MYFREE(pdata);
	  pdata = m3ua_octet2pdata(buf, nextpos, &nextpos);
	  if (buf) MYFREE(buf);
	  fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
	  m3ua_pdata_dump(pdata);
	  */


	  /* user data will be handled according to 'si' field */
	  switch (pdata->si) {
	    case 0x03: /* SCCP */
	      mtype = pdata->data[0];
	      /*
	      memcpy(&mtype, pdata.data, 1);
	      */
	      if (mtype == SCCP_MSG_TYPE_UDT) { /* Unitdata (0x09) */
		/* handle Unitdata */
		sigtran_sccp_udt(s, pdata);
	      } else {
		CRITICAL("Unknown Message Type: %d (0x%x)\n", mtype, mtype);
	      }
	      break;
	    default:
	      CRITICAL("Unknown Service Indicator (SI): %d (0x%x)\n", pdata->si, pdata->si);
	      break;
	  }
	  MYFREE(pdata);

	}
	l = l->next;
      }
      break;
    default:
      break;
  }
}

void sigtran_state_ssnm(sigtran_t *s)
{
  FTRACE();
  mytlv_t *t = NULL;
  llist_t *l = NULL;
  uint8_t mode = 0;
  uint32_t pc = 0;

  switch (s->sm->head.mtype) {
    case M3UA_MSG_TYPE_SSNM_DUNA:
      l = s->sm->tlvs;
      while (l) {
	t = (mytlv_t *) l->data;
	if (t && t->tag == 0x0012) { /* Affected Point Code */
	  memcpy(&pc, &t->val[0], 4);
	  memcpy(&mode, &pc, 1);
	  pc = ntohl(pc);
	  DTRACE("Mask: 0x%x (%u)\n", mode, mode);
	  CRITICAL("[SSNM: DUNA] Point Code: 0x%x (%u)\n", pc, pc);
	}
	l = l->next;
      }
      break;
    default:
      CRITICAL("[SSNM] mclass=0x%x (%u), mtype=0x%x (%u)\n",
	  s->sm->head.mclass, s->sm->head.mclass,
	  s->sm->head.mtype, s->sm->head.mtype);
      break;
  }
}

void sigtran_state_aspsm(sigtran_t *s)
{
  FTRACE();
  mytlv_t *t = NULL;
  llist_t *l = NULL;

  switch (s->sm->head.mtype) {
    case M3UA_MSG_TYPE_ASPSM_BEAT_ACK:
      l = s->sm->tlvs;
      while (l) {
	t = (mytlv_t *) l->data;
	if (t && t->tag == 0x0009) { /* BEAT */
	  memcpy(&s->m3ua_hb, &t->val[0], 4);
	  DTRACE("[ASPSM: BEAT_ACK] m3ua_hb = 0x%x [%d]\n", s->m3ua_hb, s->m3ua_hb);
	  //--s->m3ua_hb; /* decrement counter */
	  s->m3ua_hb = 0; /* reset to 0, to consider having fresh start */
	}
	l = l->next;
      }
      break;
    default:
      CRITICAL("[ASPSM] mclass=0x%x (%u), mtype=0x%x (%u)\n",
	  s->sm->head.mclass, s->sm->head.mclass,
	  s->sm->head.mtype, s->sm->head.mtype);
      break;
  }
}

void sigtran_state_asptm(sigtran_t *s)
{
  FTRACE();

  switch (s->sm->head.mtype) {
    default:
      CRITICAL("[ASPTM] mclass=0x%x (%u), mtype=0x%x (%u)\n",
	  s->sm->head.mclass, s->sm->head.mclass,
	  s->sm->head.mtype, s->sm->head.mtype);
      break;
  }
}

void sigtran_state_rkm(sigtran_t *s)
{
  FTRACE();

  switch (s->sm->head.mtype) {
    default:
      CRITICAL("[RKM] mclass=0x%x (%u), mtype=0x%x (%u)\n",
	  s->sm->head.mclass, s->sm->head.mclass,
	  s->sm->head.mtype, s->sm->head.mtype);
      break;
  }
}


void sigtran_state_machine(sigtran_t *s)
{
  FTRACE();

  int msg_flags = 0;
  struct sockaddr_in peeraddr = { 0 };
  struct sctp_sndrcvinfo sri = { 0 };
  socklen_t len = 0;
  uint32_t nextpos = 0;
  octet buffer[MAXBUFSIZ] = { 0 } ;
  uint32_t bufpos = 0;


  //USECDUMPR();

  len = sizeof(peeraddr);
  bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
  if (bufpos <= 0) { CRITICAL("No data received\n"); return; }

  DTRACE("From str:%d seq:%d (assoc:0x%x) [%d bytes]:\n",
      sri.sinfo_stream, sri.sinfo_ssn, (u_int) sri.sinfo_assoc_id, bufpos);
  if (msg_flags & MSG_NOTIFICATION) {
    if (sctp_handle_notification(s, buffer) < 0) {
      CRITICAL("*** NOTIFICATION LOOKS LIKE FATAL. NEEDS TO EXIT. ***\n");
      exit(EXIT_FAILURE);
    }
    return;
    //CRITICAL("Received Notification\n");
  }

#if 0
    /* testing code to check if socket is still readable after sctp_recvmsg()
     * stranglely, it is still readable and returns same data
     */
    len = sizeof(peeraddr);
    bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
    if (bufpos <= 0) fprintf(stderr, "No more data\n"); else fprintf(stderr, "Some data still read\n");

    len = sizeof(peeraddr);
    bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
    if (bufpos <= 0) fprintf(stderr, "No more data\n"); else fprintf(stderr, "Some data still read\n");

    len = sizeof(peeraddr);
    bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
    if (bufpos <= 0) fprintf(stderr, "No more data\n"); else fprintf(stderr, "Some data still read\n");

    len = sizeof(peeraddr);
    bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
    if (bufpos <= 0) fprintf(stderr, "No more data\n"); else fprintf(stderr, "Some data still read\n");

    len = sizeof(peeraddr);
    bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
    if (bufpos <= 0) fprintf(stderr, "No more data\n"); else fprintf(stderr, "Some data still read\n");
#endif


  //hexdump(buffer, bufpos);
  if (sri.sinfo_stream > MAX_ISTREAM) {
    CRITICAL("*** Ignoring message from stream %d\n", sri.sinfo_stream);
    return;
  }
  //hexdump(buffer, bufpos);

#ifdef MDEBUG
  fprintf(stderr, "-----\n");
#endif

  s->sm = octet2m3ua(buffer, bufpos, &nextpos);
  if (!s->sm) {
    CRITICAL("*** Malformed m3ua packet received, ignored.\n");
    return;
  }
  //m3ua_dump(s->sm);

  /* prepare destination m3ua */

  switch (s->sm->head.mclass) {
    case M3UA_MSG_CLASS_MGMT:
      sigtran_state_mgmt(s);
      break;
    case M3UA_MSG_CLASS_TM: /* here goes the real data */
      //m3ua_dump(s->sm);
      sigtran_state_tm(s);
      break;
    case M3UA_MSG_CLASS_SSNM:
      sigtran_state_ssnm(s);
      break;
    case M3UA_MSG_CLASS_ASPSM:
      sigtran_state_aspsm(s);
      break;
    case M3UA_MSG_CLASS_ASPTM:
      sigtran_state_asptm(s);
      break;
    case M3UA_MSG_CLASS_RKM:
      sigtran_state_rkm(s);
      break;
    default:
      break;
  }

  m3ua_free(s->sm);
  s->sm = NULL;

#if 0
    printf("%.*s", rd_sz, recvline);
#endif

}


static void *sigtran_recv_from_tcap(void *s, void *sys)
{
  FTRACE();
  uint32_t nextpos = 0;
  hook_t *h = s;
  sigtran_t *st = h->data;
  ssize_t nw = 0;
  uint64_t one = 0;
  octet *m3uabuf = NULL;
  mytlv_t *tlv = NULL;
  octet *udtbuf = NULL;
  octet *pdatabuf = NULL;

  //  static char buf[SIGTRAN_MTU];
  sigtran_tcap_info_t *sinfo = NULL;

  DTRACE("Data received from TCAP. Going to process.\n");

  nw = read(h->fd, &one, sizeof(one));
  if (nw != sizeof(one)) {
    DTRACE("Error reading from eventfd (efd)\n");
    goto end;
  }

  sinfo = lfq_dequeue(st->tcap.q_fr_tcap);
  if (!sinfo) goto end;


  /* build m3ua packet from the sinfo */
  nextpos = 0;
  udtbuf = sccp_udt2octet(sinfo->udt, &nextpos);
  if (udtbuf && nextpos > 0) {
    /* fill up sccp protocol data with udt */
    memcpy(sinfo->pdata->data, udtbuf, nextpos);
    sinfo->pdata->datalen = nextpos;
    MYFREE(udtbuf);
  }

  nextpos = 0;
  pdatabuf = m3ua_pdata2octet(sinfo->pdata, &nextpos);
  if (pdatabuf && nextpos > 0) {
    /* m3ua protocol data is ready to be sent over wire */
    tlv = mytlv_build(0x0210, pdatabuf, nextpos); /* 0x0210 == protocol data */
    m3ua_add_tlv(sinfo->m3ua, tlv);

    //m3ua_dump(sinfo->m3ua);
    //fprintf(stdout, "****\n");

    nextpos = 0;

    m3uabuf = m3ua2octet(sinfo->m3ua, &nextpos);
    DTRACE("%u bytes m3ua packet created\n", nextpos);
    MYFREE(pdatabuf);

    //fprintf(stdout, "%u bytes m3ua packet created\n", nextpos);

#if 0
    m3ua_t *tmpm3ua = NULL;
    tmpm3ua = octet2m3ua(m3uabuf, nextpos, &nextpos);
    m3ua_dump(tmpm3ua);
#endif

    if (m3uabuf && nextpos > 0) {
      /* write to wire */
      if ((nw = sctp_sendmsg(st->fd, m3uabuf, nextpos, (struct sockaddr *) &st->servaddr, st->addrlen, st->ppid, 0, st->data_str_no, 0, 0)) != nextpos) {
	CRITICAL("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nw);
      }
      USECDUMPS();
      /* when finished writing to wire, free it */
      MYFREE(m3uabuf);
    }
  }

end:
  sigtran_tcap_info_free(sinfo);

  return NULL;
}

static void *sigtran_m3ua_hb_process(void *s, void *sys)
{
  FTRACE();
  hook_t *h = s;
  sigtran_t *st = h->data;
  uint64_t timerdata = 0;
  uint32_t nextpos = 0;
  octet *buf = NULL;
  ssize_t nw = 0;

  DTRACE("*** Timer armed. Going to process.\n");

  nw = read(h->fd, &timerdata, sizeof(timerdata));
  if (nw != sizeof(timerdata)) {
    CRITICAL("Error reading from timerfd (tfd)\n");
    goto end;
  }

  ++st->m3ua_hb; /* increase, ack will decrease it */
#define SIGTRAN_M3UA_TIMER_MAX		3
  if (st->m3ua_hb > SIGTRAN_M3UA_TIMER_MAX) {
    CRITICAL("Maximum (%d) consecutive unacknowledged timer reached. Considering the peer dead. Exiting...\n", st->m3ua_hb);
    exit(EXIT_FAILURE);
  }

  buf = m3ua_octet_ASPSM_BEAT(st->m3ua_hb, &nextpos);
  if (!buf) {
    CRITICAL("Error creating M3UA ASPSM BEAT Message.\n");
    goto end;
  }

  if (buf && nextpos > 0) {
    DTRACE("Sending ASPSM BEAT [%d]\n", st->m3ua_hb);
    /* write to wire */
    if ((nw = sctp_sendmsg(st->fd, buf, nextpos, (struct sockaddr *) &st->servaddr, st->addrlen, st->ppid, 0, st->data_str_no, 0, 0)) != nextpos) {
      CRITICAL("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nw);
    }
    /* when finished writing to wire, free it */
    MYFREE(buf);
  }

end:

  return NULL;
}



/* state machine should be developed from received packets */
static void *sigtran_process_data(void *s, void *sys)
{
  FTRACE();
  sigtran_session_t *ss = (sigtran_session_t *) s;
  sigtran_t *st = (sigtran_t *) ss->data;
  //HeapProfilerDump("New Packet");
  sigtran_state_machine(st);

  return NULL;
}


static void *sigtran_on_data(void *self, void *sys)
{
  FTRACE();
  void *ret = NULL;

  sigtran_session_t *s = self;
  if (CHECKFLAG(s->ev.events, EPOLLRDHUP) ||
      CHECKFLAG(s->ev.events, EPOLLHUP) ||
      CHECKFLAG(s->ev.events, EPOLLERR)
     ) {
    CRITICAL("*** SIGTRAN socket got EPOLL{RDHUP|HUP|ERR}. Closing. This should NOT happen.\n");
    sigtran_session_close(s, (system_t *) sys);
    exit(EXIT_FAILURE);
    ret = NULL;
  } else {
    ret = s;
  }

  return ret;
}

static void *sigtran_tcap_ready(void *self, void *sys)
{
  FTRACE();
  void *ret = NULL;

  sigtran_session_t *s = self;
  if (CHECKFLAG(s->ev.events, EPOLLRDHUP) ||
      CHECKFLAG(s->ev.events, EPOLLHUP) ||
      CHECKFLAG(s->ev.events, EPOLLERR)
     ) {
    CRITICAL( "*** eventfd got EPOLL{RDHUP|HUP|ERR}. Closing. This should NOT happen.\n");
    close(s->fd);
    exit(EXIT_FAILURE);
    ret = NULL;
  } else {
    ret = s;
  }

  return ret;
}

static void *sigtran_m3ua_hb_ready(void *self, void *sys)
{
  FTRACE();
  void *ret = NULL;

  sigtran_session_t *s = self;
  if (CHECKFLAG(s->ev.events, EPOLLRDHUP) ||
      CHECKFLAG(s->ev.events, EPOLLHUP) ||
      CHECKFLAG(s->ev.events, EPOLLERR)
     ) {
    CRITICAL( "*** timerfd got EPOLL{RDHUP|HUP|ERR}. Closing. This should NOT happen. Hearbeat will be affected.\n");
    close(s->fd);
    //exit(EXIT_FAILURE);
    ret = NULL;
  } else {
    ret = s;
  }

  return ret;
}

#if 0
static void handle_signal(int signo)
{
  switch (signo) {
    case SIGPIPE:
      fprintf(stderr, "SIGPIPE handled.\n");
      close(*fd_to_tcap_ptr);
      *fd_to_tcap_ptr = -1; /* next write attempt will try to open file again */
      break;
    default:
      fprintf(stderr, "%d handled\n", signo);
      break;
  }
  return;
}
#endif

static void sigtran_tcap_init(sigtran_t *st)
{
  FTRACE();
#if 0
  signal(SIGPIPE, handle_signal);
#endif

  pthread_t tid = 0;
#if 0
  pthread_attr_t attr;
#endif


  sigtran_tcap_t *t = &st->tcap;

  t->q_to_tcap = lfq_new();
  t->q_fr_tcap = lfq_new();
  t->dfq = lfq_new();
  sem_init(&t->lock, 0, 0); /* initialize the lock (semaphore) */
  pthread_mutex_init(&t->mutex, NULL);
  t->efd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK|EFD_SEMAPHORE);

  hook_t *s = hook_new();
  if (s) {
    s->fd = t->efd;
    s->data = st;
    *(&s->ready) = sigtran_tcap_ready;
    *(&s->process) = sigtran_recv_from_tcap;
    s->ev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLET;
    s->ev.data.ptr = s;

    //EVQ_ADD(sys->eventfd, st->tcap.fd_fr_tcap, &s->ev);
    EVQ_ADD(st->sys->eventfd, s->fd, &s->ev);
  }

  t->nmaps = 1; /* how many MAP stacks running (licenses purchased) */

  /* create tcap thread */
#if 0
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif

  //pthread_create(&tid, &attr, sigtran_tcap_worker, (void *) st);
  pthread_create(&tid, NULL, sigtran_tcap_worker, (void *) st);
  pthread_detach(tid);
#if 0
  pthread_attr_destroy(&attr);
#endif
}



/* heartbeat initialization */
static void sigtran_m3ua_hb_init(sigtran_t *st)
{
  FTRACE();

#define SIGTRAN_M3UA_HB_TIMER	60
  struct timespec ts = { SIGTRAN_M3UA_HB_TIMER, 0 };
  struct itimerspec its;
  its.it_interval = ts;
  its.it_value = ts;

  st->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK);
  if (st->tfd == -1) {
    CRITICAL("Error initializing timer! Heartbeats might not be working.\n");
    return;
  }
  if (timerfd_settime(st->tfd, 0, &its, NULL) != 0) {
    close(st->tfd); st->tfd = -1;
    CRITICAL("Error setting timer! Heartbeats might not be working.\n");
    return;
  }

  hook_t *s = hook_new();
  if (s) {
    s->fd = st->tfd;
    s->data = st;
    *(&s->ready) = sigtran_m3ua_hb_ready;
    *(&s->process) = sigtran_m3ua_hb_process;
    s->ev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLET;
    s->ev.data.ptr = s;

    //EVQ_ADD(sys->eventfd, st->tcap.fd_fr_tcap, &s->ev);
    EVQ_ADD(st->sys->eventfd, s->fd, &s->ev);
  }
}

int module_start(system_t *sys)
{
  int ret = -1;

  /* configuration parameters START */
  char servaddr_str[20] = "10.21.11.2";
  int servaddr_port = 3053;
  char cliaddr_str[20] = "10.21.193.66";
  int cliaddr_port = 2905;
  struct sctp_event_subscribe evnts;
  uint32_t ugw_pc = 2228; /* ussd gw (asp) point code */
  uint32_t msc_pc = 2500; /* msc point code */
  uint8_t ugw_ssn = 147; /* gsmSCF (MAP) */
  //uint8_t ugw_ssn = 5; /* MAP */
  uint8_t hlr_ssn = 6; /* hlr */
  char ugw_gt[20] = "880150159935";
  char hlr_gt[20] = "880150159800"; /* Fixed HLR GT (for MT) */
  //char hlr_gt[] = "880150158821"; /* Load Balancing HLR GT */
  //char hlr_gt[] = "880150158822"; /* Load Balancing HLR GT */
  //char hlr_gt[] = "880150159840"; /* Load balancing HLR GT */
#ifndef UGWTEST
  char appurl[512] = "http://127.0.0.1/ussd/mo.php";
#else
  char appurl[512] = "http://127.0.0.1/ussd/test.html";
#endif
   //size_t app_url_timeout = 60; /* curl total timeout */
   //char app_url_error_msg[256] = "Service temporarily unavailable. Please try again later.";

#if 0
  char servaddr_str[20] = { 0 };
  int servaddr_port = 2905;
  char cliaddr_str[20] = { 0 };
  int cliaddr_port = 2905;
  struct sctp_event_subscribe evnts;
  uint32_t ugw_pc = 0; /* ussd gw (asp) point code */
  uint32_t msc_pc = 0; /* msc point code */
  uint8_t ugw_ssn = 147; /* gsmSCF (MAP) */
  //uint8_t ugw_ssn = 5; /* MAP */
  uint8_t hlr_ssn = 6; /* hlr */
  char ugw_gt[20] = { 0 };
  char hlr_gt[20] = { 0 }; /* Fixed HLR GT (for MT) */
  //char hlr_gt[] = "880150158821"; /* Load Balancing HLR GT */
  //char hlr_gt[] = "880150158822"; /* Load Balancing HLR GT */
  //char hlr_gt[] = "880150159840"; /* Load balancing HLR GT */
  char appurl[512] = { 0 };
#endif

#ifndef UGWTEST
#define CFGFILE "sigtran.cfg"
#else
#define CFGFILE "sigtran_test.cfg"
#endif
  FILE *cfgfp = NULL;
  char cbuf[512] = { 0 };
  char ckey[256] = { 0 };
  char cval[256] = { 0 };
  uint8_t cbuflen = 0;
  char *cptr = NULL;
  int coffset = 0;


  int sockfd = 0;
  struct sockaddr_in servaddr = { 0 }, cliaddr = { 0 };
#if 0
  char servaddr_str[] = "127.0.0.1";
  int servaddr_port = 9999;
  char cliaddr_str[] = "127.0.0.1";
  int cliaddr_port = 9998;
#endif

  ssize_t nr = 0;
  octet *buf = NULL;
  uint32_t nextpos = 0;
  struct sctp_initmsg initmsg = { 0 };

#ifdef __linux__
  int type = SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC;
#else
  int type = SOCK_SEQPACKET;
#endif
  int proto = IPPROTO_SCTP;


  cfgfp = fopen(CFGFILE, "r");
  if (!cfgfp) {
    DTRACE("*** CONFIGURATION FILE [" CFGFILE "] MISSING OR NOT READABLE ***\n");
    ret = -1;
    goto err_ret;
  }

  /* file format:
   * msc_ip=10.21.11.2
   * msc_port=3053
   * gw_ip=10.21.193.66
   * gw_port=2905
   * msc_pc=2500
   * gw_pc=2228
   * hlr_gt=880150159800
   * gw_gt=880150159935
   * hlr_ssn=6
   * gw_ssn=147
   * app_url="http://127.0.0.1/ussd/mo.php"
   * app_url_timeout = 60
   * app_url_error_msg = "Service temporarily unavailable. Please try again later."
   */
  memset(cbuf, 0, sizeof(cbuf));
  while (fgets(cbuf, sizeof(cbuf)-1, cfgfp)) {
    cbuflen = strlen(cbuf);
    if (cbuf[cbuflen-1] == '\n') {
      cbuf[--cbuflen] = '\0';
    }
    if (cbuf[cbuflen-1] == '\r') {
      cbuf[--cbuflen] = '\0';
    }


    /* file format:
     * msc_ip=10.21.11.2
     * msc_port=3053
     * gw_ip=10.21.193.66
     * gw_port=2905
     * msc_pc=2500
     * gw_pc=2228
     * hlr_gt=880150159800
     * gw_gt=880150159935
     * hlr_ssn=6
     * gw_ssn=147
     * app_url="http://127.0.0.1/ussd/mo.php"
     */
    ret = sscanf(cbuf, "%s = %s", ckey, cval);
    if (ret < 2) {
      //fprintf(stderr, "Less than two items scanned\n");
      continue;
    }
    //fprintf(stderr, "cbuf=%s, ckey=%s, cval=%s\n", cbuf, ckey, cval);

    if (strchr(ckey, '#') || strchr(cval, '#')) continue;

    coffset = 0;
    cptr = cval;
    if ((cptr = strchr(cptr, '"'))) {
      *cptr = '\0';
      coffset = 1;
      cptr = cval + coffset;
      if ((cptr = strrchr(cptr, '"'))) {
	*cptr = '\0';
      }
    }

    cptr = cval + coffset;

    if (strcmp(ckey, "msc_ip") == 0) {
      strcpy(servaddr_str, cptr);
    } else if (strcmp(ckey, "msc_port") == 0) {
      servaddr_port = atoi(cptr);
    } else if (strcmp(ckey, "gw_ip") == 0) {
      strcpy(cliaddr_str, cptr);
    } else if (strcmp(ckey, "gw_port") == 0) {
      cliaddr_port = atoi(cptr);
    } else if (strcmp(ckey, "msc_pc") == 0) {
      msc_pc = (uint32_t) atoi(cptr);
    } else if (strcmp(ckey, "gw_pc") == 0) {
      ugw_pc = atoi(cptr);
    } else if (strcmp(ckey, "gw_pc") == 0) {
      ugw_pc = atoi(cptr);
    } else if (strcmp(ckey, "hlr_gt") == 0) {
      strcpy(hlr_gt, cptr);
    } else if (strcmp(ckey, "gw_gt") == 0) {
      strcpy(ugw_gt, cptr);
    } else if (strcmp(ckey, "hlr_ssn") == 0) {
      hlr_ssn = (uint8_t) atoi(cptr);
    } else if (strcmp(ckey, "gw_ssn") == 0) {
      ugw_ssn = (uint8_t) atoi(cptr);
    } else if (strcmp(ckey, "app_url") == 0) {
      strcpy(appurl, cptr);
    }

    //url_system_init(); /* initialize curl subsystem */

    /*
    else if (strcmp(ckey, "app_url_timeout") == 0) {
      app_url_timeout = (size_t) atoi(cptr);
    } else if (strcmp(ckey, "app_url_error_msg") == 0) {
      strcpy(app_url_error_msg, cptr);
    }
    */

    DTRACE("ckey=<%s>, cptr=<%s>\n", ckey, cptr);
  }

  fclose(cfgfp);
  /* configuration parameters END */

#ifdef MTRACE
  mtrace();
#endif


  sockfd = socket(AF_INET, /* family */
      type, /* type */
      proto); /* protocol */
  if (sockfd == -1) {
    err_warn("socket");
    return -1;
  }

  /* set socket options to re-bind to same port in case program cashes abnormally and there's some unfinished packet (TIME_WAIT) */
  int one = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));


  /* bind to specific port */
  memset(&cliaddr, 0, sizeof(cliaddr));
  cliaddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, cliaddr_str, &cliaddr.sin_addr) == 0) {
    err_warn("inet_pton: cliaddr_str");
    goto err_ret;
  }
  cliaddr.sin_port = htons(cliaddr_port);

  if (bind(sockfd, (struct sockaddr *) &cliaddr, sizeof(cliaddr)) == -1) {
    err_warn("bind");
    goto err_ret;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, servaddr_str, &servaddr.sin_addr) == 0) {
    err_warn("inet_pton: servaddr_str");
    goto err_ret;
  }
  servaddr.sin_port = htons(servaddr_port);


  memset(&evnts, 0, sizeof(evnts));
  /* set the events we want to be notified for */
  evnts.sctp_data_io_event = 1;
  evnts.sctp_association_event = 1;
  evnts.sctp_send_failure_event = 1;
  //evnts.sctp_address_event = 1; // unnecessarily makes confusion
  evnts.sctp_peer_error_event = 1;
  evnts.sctp_shutdown_event = 1;
  evnts.sctp_adaptation_layer_event = 1;
  if (setsockopt(sockfd, IPPROTO_SCTP, SCTP_EVENTS, &evnts, sizeof(evnts)) != 0) {
    err_warn("setsockopt: evnts");
    goto err_ret;
  }

  memset(&initmsg, 0, sizeof(initmsg));
  initmsg.sinit_num_ostreams = MAX_OSTREAM;
  initmsg.sinit_max_instreams = MAX_ISTREAM;
  initmsg.sinit_max_attempts = MAX_ATTEMPTS;
  if (setsockopt(sockfd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) != 0) {
    err_warn("setsockopt: initmsg");
    goto err_ret;
  }

#if 0
  struct linger ling = { 1, 1 };
  setsockopt(sys->aws.sockfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)); /* graceful */
  one = 1;
  setsockopt(sys->aws.sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#endif

  sigtran_t *st = MYCALLOC(1, sizeof(sigtran_t));
  st->ppid = htonl(0x03); /* Payload Protocol Identifier (0x03 = M3UA) */
  st->mgmt_str_no = 0x00; /* Management messages always sent over stream 0 */
  st->data_str_no = 0x01; /* DATA messages can be sent through stream 1 onwards (in future for load balance we can send back to received-stream */
  sigtran_ptr = st;
  st->sys = sys;
  sys->sigtran = st; /* so that http module can get hold of sigtran through system_t * */
  hook_t *s = hook_new();
  if (s) {
    st->fd = s->fd = sockfd;
    st->servaddr = servaddr;
    st->addrlen = sizeof(servaddr);
    st->ugw_pc = ugw_pc;
    st->msc_pc = msc_pc;
    st->ugw_ssn = ugw_ssn;
    st->hlr_ssn = hlr_ssn;
    strcpy(st->ugw_gt, ugw_gt);
    strcpy(st->hlr_gt, hlr_gt); /* useful for USSD MT */
    s->data = st;
    strcpy(st->appurl, appurl);
    //st->app_url_timeout = app_url_timeout;
    //strcpy(st->app_url_error_msg, app_url_error_msg);

    *(&s->ready) = sigtran_on_data;
    *(&s->process) = sigtran_process_data;
    s->ev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLET;
    s->ev.data.ptr = s;
  } else {
    close(sockfd);
    exit(EXIT_FAILURE);
  }


  EVQ_ADD(sys->eventfd, sockfd, &s->ev);


  sigtran_tcap_init(st);
  sigtran_m3ua_hb_init(st); /* initialize heartbeat (m3ua layer) */



  /* this is going to be put in the sctp notification handler
   * because if network interface is interrupted it takes time
   * for association to notice it. when the association is back again
   * we should re-initialize the application
   */
  /* just ignite the fire */
  buf = m3ua_octet_ASPUP(&nextpos);

  if (!buf) {
    CRITICAL("ASPUP packet not created\n");
  } else {
    while (1) {
      CRITICAL("Sending ASPUP\n");
      if ((nr = sctp_sendmsg(sockfd, buf, nextpos, (struct sockaddr *) &servaddr, sizeof(servaddr), st->ppid, 0, st->mgmt_str_no, 0, 0)) != nextpos) {
	CRITICAL("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nr);
	sleep(1);
	//exit(EXIT_FAILURE);
      } else {
	break;
      }
    }
    MYFREE(buf);
  }
#if 0
  sctp_sendmsg(sockfd, "Hello\n", 6, (struct sockaddr *) &servaddr, sizeof(servaddr), st->ppid, 0, st->data_str_no, 0, 0);
#endif

  //HeapProfilerStart("ugwheap");

  return sockfd;

err_ret:
  if (sockfd > 0) close(sockfd);
  exit(EXIT_FAILURE);
  return ret;
}

int module_stop(system_t *sys, module_t *mod)
{
  if (mod && mod->fd > 0) close(mod->fd);
  /*
   * closing the descriptor automatically removes it from the event
  EVQ_DEL(sys->eventfd, mod->fd);
  */
  return 0;
}
