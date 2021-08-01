/*
 * url-test.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "url-utils.h"

int main(void)
{
  url_system_init();

  url_t *url_handle = url_handle_new();
  char *var = "My User Name";
  char *url = "http://localhost/ussd/ayub-mo.php";
  char urlbuf[1024];
  char q[2];
  size_t size = 0;
  q[1] = '\0';
  if (strchr(url, '?')) {
    q[0] = '\0'; /* nothing to add */
  } else {
    q[0] = '?'; /* add query string */
  }
  char *escaped = url_encode(url_handle, var, &size);
  if (escaped) {
    sprintf(urlbuf, "%s%sname=%s", url, q, escaped);
    url_encode_free(escaped);
    fprintf(stderr, "Length: %lu\nURL: [%s]\n", size, urlbuf);
    char *contents = url_get_contents(url_handle, urlbuf, &size);
    fprintf(stderr, "Length: %lu\nData: [%s]\n", size, contents);
    free(contents);
  }
  url_handle_free(url_handle);

  url_system_cleanup();
  return 0;
}
