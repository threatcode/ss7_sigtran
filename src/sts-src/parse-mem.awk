#!/usr/bin/awk -f

BEGIN {
  FS = "|";
}

{
  ptr = $1;
  sign = substr(ptr, 1, 1);
  p = substr(ptr, 2);
  if (sign == "+") {
    mem[p] = $0;
  } else if (sign == "-") {
    delete mem[p];
  }
}

END {
  for (p in mem) {
    print mem[p];
  }
}
