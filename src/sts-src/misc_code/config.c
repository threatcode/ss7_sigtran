/*
 * config.c
 * system initializer according to ini (core.ini) file
 */
#include "config.h"
#include "minIni.h"



static int config_callback(const char *section, const char *key, const char *value, const void *userdata)
{
  system_t *sys = (system_t *) userdata;

  static int core_defined = 0; /* core section must come at first */
  static char lastsection[32];

  if (!core_defined && section && section[0] && !strncmp(section, "core", 4)) {
    /*
     * fprintf(stderr, "Reading core section...\n");
     */
    core_defined = 1;
    fprintf(stderr, "System Allocated on %p\n", sys);
  }
  if (!core_defined) {
    fprintf(stderr, "[core] section must come at first. Can not proceed with configuration. Abort.\n");
    abort();
    return 0;
  }

  if (strcmp(section, lastsection)) { /* new section */
    strncpy(lastsection, section, sizeof(lastsection)-1);
    lastsection[sizeof(lastsection)-1] = '\0';
  }

  printf("	[%s]\t%s=%s\n", section, key, value);
  return 1; /* true */
}

#ifdef TEST_CONFIG
int main(int argc, char **argv)
{
  system_t *sys = (system_t *) CALLOC(1, sizeof(system_t));

  const char *configfile = "core.ini";
  ini_browse(config_callback, sys, configfile);
  return 0;
}
#endif
