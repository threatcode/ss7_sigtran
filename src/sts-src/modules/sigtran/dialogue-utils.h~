/*
 * dialogue-utils.h
 */
#ifndef _DIALOGUE_UTILS_H_
#define _DIALOGUE_UTILS_H_

#include <TCMessage.h>

ExternalPDU_t *ati_dialogue_request_build(void);
void ati_dialogue_request_free(ExternalPDU_t *ext);
ExternalPDU_t *ussd_dialogue_request_build(const char *destnum, const char *srcnum);
void ussd_dialogue_request_free(ExternalPDU_t *ext);
ExternalPDU_t *ussd_dialogue_response_accepted(void);
void ussd_dialogue_response_free(ExternalPDU_t *ext);
void camel_ati_dialogue_request_free(ExternalPDU_t *ext);

#endif
