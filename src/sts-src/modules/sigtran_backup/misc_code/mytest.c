/*
 * mytest.c
 */

#include "sigtran_http_resp_func.c"

int extract_tokens(const char *query_string, char *msisdn, size_t msisdn_len, char *text, size_t text_len, uint8_t *notify_only);


int main(int argc, char **argv)
{
  const char *query_string = "msisdn=8801534619955&text=hello\%20ayub&flow=begin";
  char msisdn[20];
  char text[256];
  uint8_t notify_only = 1;

  fprintf(stderr, "%s\n", query_string);

  extract_tokens(query_string, msisdn, sizeof(msisdn), text, sizeof(text), &notify_only);

  fprintf(stderr, "msisdn=%s, text=%s, notify_only=%u\n", msisdn, text, notify_only);

  return 0;
}
