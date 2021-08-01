/*
 * common.c
 */
#include "common.h"

void system_free(system_t *sys)
{
  register int i;
  module_t *mod = NULL;
  if (sys) {
    FREE_IT(sys->moduledir);
    if (sys->modules) {
      for (i = 0; sys->modules[i]; ++i)
	module_unload(sys->modules[i]);
	module_free(sys->modules[i]);
      }
    }
    FREE_IT(sys->modules);
  }
}
