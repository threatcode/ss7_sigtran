/*
 * module.h
 */
#ifndef __MODULE_H__
#define __MODULE_H__

#include "main.h"

typedef struct {
  char name[32];
  int fd; /* needed for stopping the module */
  void *handle; /* the module handle */
} module_t;

/* modules will implement following functions */
extern int module_start(system_t *sys);
extern int module_stop(system_t *sys, module_t *mod);

#define module_new() calloc(1, sizeof(module_t))

#endif
