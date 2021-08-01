#!/bin/bash

OPT="${LPATH}"
pushd src
make
cp -fv libosmo-asn1-tcap.so ${OPT}/lib/
popd

echo "Installing Header Files"
rsync -a include/ ${OPT}/include/tcap/
