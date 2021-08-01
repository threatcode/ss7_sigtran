#!/bin/bash

OPT="/opt/local"
pushd src
make
cp -fv libosmo-asn1-tcap.so ${OPT}/osmo/lib/
popd

echo "Installing Header Files"
rsync -a include/ ${OPT}/osmo/include/tcap/
