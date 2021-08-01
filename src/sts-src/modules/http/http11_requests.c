/*
 * http11_requests.c
 */
#include "http11_requests.h"


#ifdef USE_MPH
/*
#define HTTP_REQUESTS_FILE "/usr/share/dict/cracklib-words"
*/
#define HTTP_REQUESTS_FILE "/home/ayub/ayubd-ng/modules/http/http11_requests_nl.txt"
#if 0
#define HTTP_REQUESTS_FILE "/usr/share/dict/cracklib-words"
#endif

static mph_tab_t *http11_requests_htab;

int hrq_init(void)
{   
  http11_requests_htab = mph_load_file(HTTP_REQUESTS_FILE);
  return 0;
}

void hrq_free(void)
{
  if (http11_requests_htab) mph_unload(http11_requests_htab);
}

int hrq_key_id(const char *key, size_t len)
{
  return mph_search_key_id(http11_requests_htab, key, len);
}

hrq_key_t *hrq_key(unsigned int id)
{
  return mph_search_id(http11_requests_htab, id);
}
#endif
