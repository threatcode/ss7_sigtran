#!/bin/bash

source env.sh

pushd ${SS7_SRC}

CDIR="`pwd`"

for slib in ${SS7_LIBS}; do
  if [ -x "${CDIR}/${slib}.build.sh" ]; then
    build_script="${CDIR}/${slib}.build.sh"
  else
    continue
  fi
  pushd $slib
    ${build_script}
  popd
done



popd
