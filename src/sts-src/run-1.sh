#!/bin/bash

pushd ${HOME}/ayubd-ng

ALLOCATOR="/usr/lib64/libtcmalloc_minimal.so"
#ALLOCATOR="/usr/lib64/libjemalloc.so"
maxcnt=100
trap "killall -INT ayubd; exit" SIGINT
#count=1; while [ $count -lt $maxcnt ]; do LD_PRELOAD="${ALLOCATOR}" ./ayubd 2>&1 | tee run-${count}.log; count=$((count+1)); echo "Quit on `date`" >> lastquit.log; sleep 3; done
count=1; while [ $count -lt $maxcnt ]; do ./ayubd 2>&1 | tee run-${count}.log; count=$((count+1)); echo "Quit on `date`" >> lastquit.log; sleep 3; done
popd
