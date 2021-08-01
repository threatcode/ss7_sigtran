/*
 * main.c
 */
#include "main.h"

int main(int argc, char **argv)
{
  read_config();
  load_modules();
  run_system();

  return 0;
}
