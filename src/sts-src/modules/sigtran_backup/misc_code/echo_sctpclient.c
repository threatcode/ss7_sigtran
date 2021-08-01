/*
 * echo_sctpclient.c
 * echo client in sctp
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
  int sock_fd;
  int port = 9999;
  struct sockaddr_in servaddr;
  struct sctp_event_subscribe evnts;

  if (argc < 2) {
    echo("host argument needed\n");
    die();
  }

  echo("Creating socket ...");
  sock_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (sock_fd == -1) die();
  ok();
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  inet_pton(AF_INET, argv[1], &servaddr.sin_addr);
  servaddr.sin_port = htons(port);

#if 0
  fprintf(stderr, "Binding socket on *:%d...", port);
  if (bind(sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0) die();
  ok();
#endif

  memset(&evnts, 0, sizeof(evnts));
  evnts.sctp_data_io_event = 1;
  echo("Setting socket option: evnts ...");
  if (setsockopt(sock_fd, IPPROTO_SCTP, SCTP_EVENTS, &evnts, sizeof(evnts)) != 0) die();
  ok();

#if 0
  echo("Listening ...");
  if (listen(sock_fd, 5) != 0) die();
  ok();
#endif

  sctp_echo_cli(stdin, sock_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
  close(sock_fd);

  return 0;
}
