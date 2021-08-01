#!/usr/bin/awk -f

BEGIN {
  exit;
  FS = "|";
  f1 = "count-1.log";
  f2 = "count-14.log";

  while (getline < f1) {
    p = substr($1, 1);
    mem[p] = $0;
  }
  close(f1);

  while (getline < f2) {
    p = substr($1, 1);
    if (p in mem) delete mem[p];
    else mem[p] = $0;
  }
  close(f2);

  for (p in mem) {
    print mem[p];
  }
  exit;
}


END {
}
