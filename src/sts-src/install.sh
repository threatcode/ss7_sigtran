#!/bin/bash

INSTROOT="/stgw"
mkdir -p ${INSTROOT}/modules
EXENAME="stgw"
cp -vf ${EXENAME} ${INSTROOT}
for module in http license signal sigtran; do mkdir -p ${INSTROOT}/modules/$module; cp -vf modules/$module/mod_$module.so ${INSTROOT}/modules/$module/mod_$module.so; done
