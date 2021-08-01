#!/bin/bash

#echo "Please keep backup of ../include/{AARE,AARQ,ABRT}-apdu.h and then remove this line from script and re-execute it"
#echo "Ayub <ayub@nixtecsys.com> made some changes in those headers to make them work"
#exit 1

F="../include/EXTERNAL.h"

if [ ! -f "${F}" ]; then
cat > ${F} <<EOF
#ifndef _TCAP_EXTERNAL_h
#define _TCAP_EXTERNAL_h

/* This file is added manually to make asn1c output build at all */

#include <ANY.h>

typedef ANY_t EXTERNAL_t;
#define asn_DEF_EXTERNAL asn_DEF_ANY

#endif /* _TCAP_EXTERNAL_h */
EOF
fi


ASN=../asn
#asn1c $ASN/DialoguePDUs.asn $ASN/tcap.asn $ASN/UnidialoguePDUs.asn 
asn1c -Wdebug-lexer $ASN/DialoguePDUs.asn $ASN/tcap.asn $ASN/UnidialoguePDUs.asn 
#asn1c -Wdebug-lexer $ASN/DialoguePDUs.asn $ASN/TCAPMessages.asn $ASN/UnidialoguePDUs.asn 
find . -type l -exec rm \{\} \;
mv *.h ../include/
