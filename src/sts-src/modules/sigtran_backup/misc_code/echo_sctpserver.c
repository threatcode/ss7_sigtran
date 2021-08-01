/*
 * echo_sctpserver.c
 * echo server in sctp
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <unistd.h>

#include "utils.h"

#define die() exit(EXIT_FAILURE)
#define echo(str) fprintf(stderr, str)
#define ok() fprintf(stderr, " [  OK  ]\n")
#define fail() fprintf(stderr, " [FAILED]\n")


int main(int argc, char **argv)
{
  int sock_fd, msg_flags;
  char readbuf[512];
  int port = 9999;
  struct sockaddr_in servaddr, cliaddr;
  struct sctp_sndrcvinfo sri;
  struct sctp_event_subscribe evnts;
  int stream_increment = 1;
  socklen_t len;
  size_t rd_sz;

  if (argc == 2) {
    stream_increment = atoi(argv[1]);
  }
  echo("Creating socket ...");
  sock_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (sock_fd == -1) die();
  ok();
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  fprintf(stderr, "Binding socket on *:%d...", port);
  if (bind(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) die();
  ok();

  memset(&evnts, 0, sizeof(evnts));
  evnts.sctp_data_io_event = 1;
  echo("Setting socket option: evnts ...");
  if (setsockopt(sock_fd, IPPROTO_SCTP, SCTP_EVENTS, &evnts, sizeof(evnts)) != 0) die();
  ok();

  echo("Listening ...");
  if (listen(sock_fd, 5) != 0) die();
  ok();

  while (1) {
    len = sizeof(struct sockaddr_in);
    rd_sz = sctp_recvmsg(sock_fd, readbuf, sizeof(readbuf), (struct sockaddr *) &cliaddr, &len, &sri, &msg_flags);
    if (rd_sz > 0) {
      write(2, readbuf, rd_sz);
      hexdump(readbuf, rd_sz);
    }
    if (stream_increment) {
      sri.sinfo_stream++;
      if (sri.sinfo_stream >= sctp_get_no_strms(sock_fd, (struct sockaddr *) &cliaddr, len)) sri.sinfo_stream = 0;
    }
    echo("Sending data back to client ...");
    if (sctp_sendmsg(sock_fd, readbuf, rd_sz, (struct sockaddr *) &cliaddr, len, sri.sinfo_ppid, sri.sinfo_flags, sri.sinfo_stream, 0, 0) == -1) die();
    ok();
  }

  return 0;
}
