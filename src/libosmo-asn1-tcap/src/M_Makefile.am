# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=0:0:0

INCLUDES = $(all_includes) -I/usr/local/include/asn1c -I$(top_srcdir)/include
AM_CFLAGS = -fPIC -Wall

libosmo_asn1_tcap_la_SOURCES =	\
	DialoguePDU.c	\
	AARQ-apdu.c	\
	AARE-apdu.c	\
	RLRQ-apdu.c	\
	RLRE-apdu.c	\
	ABRT-apdu.c	\
	ABRT-source.c	\
	Associate-result.c	\
	Associate-source-diagnostic.c	\
	Release-request-reason.c	\
	Release-response-reason.c	\
	ExternalPDU.c	\
	Dialog1.c	\
	TCMessage.c	\
	Unidirectional.c	\
	Begin.c	\
	End.c	\
	Continue.c	\
	Abort.c	\
	Reason.c	\
	DialoguePortion.c	\
	DialogueOC.c	\
	OrigTransactionID.c	\
	DestTransactionID.c	\
	P-AbortCause.c	\
	ComponentPortion.c	\
	Component.c	\
	Invoke.c	\
	Parameter.c	\
	ReturnResult.c	\
	ReturnError.c	\
	Reject.c	\
	InvokeIdType.c	\
	OPERATION.c	\
	ERROR.c	\
	GeneralProblem.c	\
	InvokeProblem.c	\
	ReturnResultProblem.c	\
	ReturnErrorProblem.c	\
	ErrorCode.c	\
	UniDialoguePDU.c	\
	AUDT-apdu.c

lib_LTLIBRARIES=libosmo-asn1-tcap.la
