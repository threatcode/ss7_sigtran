/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* A multi-threaded example that uses pthreads extensively to fetch
 * X remote files at once */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <curl/curl.h>
#include <sys/time.h>

static const long ctimeout = 30; /* connect timeout */
static const long ttimeout = 30; /* transfer timeout */

static const char *ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36";
static const char *rr = "http://indianvisaonline.gov.in/visa/indianVisaReg.jsp";

static void set_opts(CURL *curl)
{
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, ctimeout);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, ttimeout);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, ua);
  curl_easy_setopt(curl, CURLOPT_REFERER, rr);
}

#if 0
static double get_msecs(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}
#endif

static void *pull_one_url(void *fname)
{
  char *url = "http://indianvisaonline.gov.in/visa/Rimage.jsp";
  CURL *curl = NULL;
  CURLcode res;

  FILE *fp = fopen((char *) fname, "w");
  if (!fp) goto end;

  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url);
  set_opts(curl);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) fp);
  res = curl_easy_perform(curl); /* ignores error */
  curl_easy_cleanup(curl);
  fclose(fp);

  if (res == CURLE_OK) {
    printf("%s:OK\n", (char *) fname);
  } else {
    printf("%s:FA\n", (char *) fname);
  }

end:
  free(fname);
  pthread_exit(NULL);

  return NULL;
}


/*
   int pthread_create(pthread_t *new_thread_ID,
   const pthread_attr_t *attr,
   void * (*start_func)(void *), void *arg);
*/

int main(int argc, char **argv)
{
  if (argc != 2) return 1;

  pthread_t *tid = NULL;
  int n = 0;
  char *infile = argv[1];
  FILE *in = fopen(infile, "r");

  int i;
  int error;
  size_t len = 0;
  char *fname = NULL;

  /* Must initialize libcurl before any threads are started */
  
  curl_global_init(CURL_GLOBAL_ALL);

  char buf[4096];
  if (!fgets(buf, sizeof(buf), in)) {
    fprintf(stderr, "First line missing\n");
  }
  len = strlen(buf);
  if (buf[len-1] == '\n') { len--; buf[len] = '\0'; }

  n = atoi(buf);
  tid = calloc(n, sizeof(pthread_t));

  //long start = get_msecs();
  //fprintf(stderr, "Start time: %ld msec\n", start);
  for (i = 0; i < n; ++i) {
    if (fgets(buf, sizeof(buf), in)) {
      len = strlen(buf);
    } else {
      len = 0;
    }

    if (buf[len-1] == '\n') { len--; buf[len] = '\0'; }
    fname = strdup(buf); /* thread will free it */
    error = pthread_create(&tid[i],
	NULL, /* default attributes please */
	pull_one_url,
	(void *) fname);
    if ( 0 != error)
      fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
    /*
    else
      fprintf(stderr, "Thread %d executed\n", i);
      */
  }

  void *retval = NULL;
  /* now wait for all threads to terminate */
  for (i = 0; i < n; ++i) {
    error = pthread_join(tid[i], &retval);
    /*
    fprintf(stderr, "Thread %d terminated\n", i);
    */
  }
  //long end = get_msecs();
  //fprintf(stderr, "End time: %ld msec\n", end);
  //fprintf(stdout, "Total time taken to get %d access codes: %ld milliseconds\n", n, end-start);

  return 0;
}
