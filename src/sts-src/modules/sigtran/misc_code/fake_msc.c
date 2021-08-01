/*
 * fake_msc.c
 * imitate a msc, backed by HLR
 * Ayub <ayub@nixtecsys.com>
 * Wrote for finding TPS of the USSD Gateway developed by Ayub
 */
int main(int argc, char *argv[])
{
  int ret = -1;

  /* configuration parameters START */
  char servaddr_str[20] = "127.0.0.1";
  int servaddr_port = 3053;
  char cliaddr_str[20] = "127.0.0.1";
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
      msc_pc= (uint32_t) atoi(cptr);
    } else if (strcmp(ckey, "gw_pc") == 0) {
      ugw_pc= atoi(cptr);
    } else if (strcmp(ckey, "gw_pc") == 0) {
      ugw_pc= atoi(cptr);
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

  /* bind to specific port */
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, servaddr_str, &servaddr.sin_addr) == 0) {
    err_warn("inet_pton: server");
    goto err_ret;
  }
  servaddr.sin_port = htons(servaddr_port);

  if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1) {
    err_warn("bind");
    goto err_ret;
  }

  memset(&cliaddr, 0, sizeof(cliaddr));
  cliaddr.sin_family = AF_INET;
  if (inet_pton(AF_INET, cliaddr_str, &cliaddr.sin_addr) == 0) {
    err_warn("inet_pton: client");
    goto err_ret;
  }
  cliaddr.sin_port = htons(cliaddr_port);


  memset(&evnts, 0, sizeof(evnts));
  //evnts.sctp_association_event = 1;
  evnts.sctp_data_io_event = 1;
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


  len = sizeof(cliaddr);
  bufpos = sctp_recvmsg(s->fd, buffer, sizeof(buffer), (struct sockaddr *) &peeraddr, &len, &sri, &msg_flags);
  DTRACE("From str:%d seq:%d (assoc:0x%x) [%d bytes]:\n",
      sri.sinfo_stream, sri.sinfo_ssn, (u_int) sri.sinfo_assoc_id, bufpos);
  //hexdump(buffer, bufpos);
  if (sri.sinfo_stream > MAX_ISTREAM) {
    DTRACE("*** Ignoring message from stream %d\n", sri.sinfo_stream);
    return;
  }


  /* just ignite the fire */
  buf = m3ua_octet_ASPUP(&nextpos);

  if (!buf) {
    DTRACE("ASPUP packet not created\n");
  } else {
    DTRACE("Sending ASPUP\n");
    if ((nr = sctp_sendmsg(sockfd, buf, nextpos, (struct sockaddr *) &servaddr, sizeof(servaddr), st->ppid, 0, st->mgmt_str_no, 0, 0)) != nextpos) {
      DTRACE("Less data written to socket, attempted %u bytes, written %ld bytes\n", nextpos, nr);
    }
  }
  free(buf);
#if 0
  sctp_sendmsg(sockfd, "Hello\n", 6, (struct sockaddr *) &servaddr, sizeof(servaddr), st->ppid, 0, st->data_str_no, 0, 0);
#endif


  return sockfd;

err_ret:
  if (sockfd > 0) close(sockfd);
  return ret;
}
