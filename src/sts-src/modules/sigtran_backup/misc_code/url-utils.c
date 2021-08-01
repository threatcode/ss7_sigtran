/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* Example source code to show how the callback function can be used to
 * download data into a chunk of memory instead of storing it in a file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "url-utils.h"
#include "defs.h"

#define UA	"nixtec-ussdgw/1.0"


static const long ctimeout = 30; /* connect timeout */
static const long ttimeout = 60; /* transfer timeout */


struct MemoryStruct {
  char *memory;
  size_t size;
  size_t allocated;
};

/* set common options */
static void url_set_opts(url_t *url_handle)
{ 
  curl_easy_setopt(url_handle, CURLOPT_CONNECTTIMEOUT, ctimeout);
  curl_easy_setopt(url_handle, CURLOPT_TIMEOUT, ttimeout);
  curl_easy_setopt(url_handle, CURLOPT_USERAGENT, UA);
//  curl_easy_setopt(curl, CURLOPT_REFERER, rr);
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  //struct MemoryStruct *mem = (struct MemoryStruct *) userp;
  struct MemoryStruct *mem = userp;

  if ((mem->size + realsize) >= mem->allocated) {
    mem->memory = MYREALLOC(mem->memory, mem->size + realsize + 1); /* +1 for NUL character */
    if (mem->memory == NULL) {
      /* out of memory! */
      CRITICAL("*** not enough memory (realloc returned NULL)\n");
      return 0;
    }
    mem->allocated = mem->size + realsize + 1;
  }

  memcpy(mem->memory+mem->size, contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = '\0';

  return realsize;
}


void url_system_init(void)
{
  curl_global_init(CURL_GLOBAL_ALL);
}

url_t *url_handle_new(void)
{
  return curl_easy_init();
}

void url_handle_free(url_t *url_handle)
{
  curl_easy_cleanup(url_handle);
}

#define CHUNK_INIT_SIZE		192
char *url_get_contents(url_t *url_handle, const char *url, size_t *size)
{
  CURLcode res = { 0 };
  struct MemoryStruct *chunk = MYCALLOC(1, sizeof(*chunk));
  char *ret = NULL;

  if (size) *size = 0;

  chunk->memory = MYMALLOC(CHUNK_INIT_SIZE);  /* will be grown as needed by the realloc above */
  if (!chunk->memory) {
    CRITICAL("chunk->memory allocation failed.\n");
    return NULL;
  }
  chunk->allocated = CHUNK_INIT_SIZE;
  chunk->size = 0;    /* no data at this point */

  //url_init(); /* will be called by caller */

  /* init the curl session */
  //curl_handle = url_handle_new();

  /* specify URL to get */
  curl_easy_setopt(url_handle, CURLOPT_URL, url);

  /* send all data to this function  */
  curl_easy_setopt(url_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt(url_handle, CURLOPT_WRITEDATA, (void *) chunk);

  url_set_opts(url_handle);

  /* get it! */
  res = curl_easy_perform(url_handle);

  /* check for errors */
  if (res != CURLE_OK) {
    MYFREE(chunk->memory);
    MYFREE(chunk);
    return NULL;
    //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
  }

  /* cleanup curl stuff */
  //url_handle_free(curl_handle);

  /*
  if(chunk.memory)
    MYFREE(chunk.memory); // caller will free it
    */

  /* we're done with libcurl, so clean it up */
  //curl_global_cleanup();
  if (size) *size = chunk->size;
  ret = chunk->memory;

  MYFREE(chunk); /* only free the struct, the contents will be freed by caller */

  return ret;
}


void url_system_cleanup(void)
{
  curl_global_cleanup();
}

/* initially size will contain the length of the string */
/* should free using url_encode_free() */
char *url_encode(url_t *url_handle, const char *value, size_t *size)
{
#define MAXLEN_URL	4096
  char *escaped = NULL;
  int len = 0;

  if (size) len = *size;
  else len = strlen(value);
  if (len <= 0 || len > MAXLEN_URL) len = strlen(value);
  escaped = curl_easy_escape(url_handle, value, len);
  if (escaped && size) {
    *size = strlen(escaped);
  }

  return escaped;
}

