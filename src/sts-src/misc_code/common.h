/*
 * common.h
 */
#ifndef __COMMON_H__
#define __COMMON_H__
#include <stdio.h>
#include <string.h>
#if 0
#include <stdlib.h>
#endif
#include <search.h>

#include "module.h"

#define FREE_IT(x) do { if (x) free(x); } while (0)

typedef struct {
  char *moduledir;
  module_t *modules;
} system_t;

void system_free(system_t *sys);

#endif
