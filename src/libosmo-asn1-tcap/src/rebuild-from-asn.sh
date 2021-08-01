#!/bin/bash

#echo "Please keep backup of ../include/{AARE,AARQ,ABRT}-apdu.h and then remove this line from script and re-execute it"
#echo "Ayub <ayub@nixtecsys.com> made some changes in those headers to make them work"
#exit 1

ASN=../asn
#asn1c $ASN/DialoguePDUs.asn $ASN/tcap.asn $ASN/UnidialoguePDUs.asn 
asn1c -Wdebug-lexer $ASN/DialoguePDUs.asn $ASN/tcap.asn $ASN/UnidialoguePDUs.asn 
#asn1c -Wdebug-lexer $ASN/DialoguePDUs.asn $ASN/TCAPMessages.asn $ASN/UnidialoguePDUs.asn 
find . -type l -exec rm \{\} \;
mv *.h ../include/
