/*
 * msisdn-test.c
 */
#include "utils.h"

int main(void)
{
  /* MSISDN (MAP) */
  uint8_t msisdn_buf[] = { 0x91, 0x88, 0x10, 0x35, 0x64, 0x91, 0x59, 0xf5 };
  uint8_t msisdn_encoded_buf[20];
  char msisdn_dec[20];
  uint8_t msisdn_len = 0;

  decode_msisdn(msisdn_buf, sizeof(msisdn_buf), msisdn_dec, &msisdn_len);
  hexdump(msisdn_buf, sizeof(msisdn_buf));
  fprintf(stderr, "Decoded MAP MSISDN [%u]: %s\n", msisdn_len, msisdn_dec);
  encode_msisdn(msisdn_dec, msisdn_len, msisdn_encoded_buf, &msisdn_len);
  fprintf(stderr, "Encoded MAP MSISDN [%u]:\n", msisdn_len);
  hexdump(msisdn_encoded_buf, msisdn_len);

  /* GT (MAP) */
  uint8_t gt_buf[] = { 0x91, 0x88, 0x10, 0x05, 0x51, 0x99, 0x53 };
  uint8_t gt_encoded_buf[20];
  char gt_dec[20];
  uint8_t gt_len = 0;

  decode_msisdn(gt_buf, sizeof(gt_buf), gt_dec, &gt_len);
  hexdump(gt_buf, sizeof(gt_buf));
  fprintf(stderr, "Decoded MAP GT [%u]: %s\n", gt_len, gt_dec);
  encode_msisdn(gt_dec, gt_len, gt_encoded_buf, &gt_len);
  fprintf(stderr, "Encoded MAP GT [%u]:\n", gt_len);
  hexdump(gt_encoded_buf, gt_len);

  /* Called Party (SCCP) */
  uint8_t sccp_gt_buf[] = { 0x88, 0x10, 0x05, 0x51, 0x88, 0x32 };
  uint8_t sccp_gt_encoded_buf[20];
  char sccp_gt_dec[20];
  uint8_t sccp_gt_len = 0;

  decode_called_party(sccp_gt_buf, sizeof(sccp_gt_buf), sccp_gt_dec, &sccp_gt_len);
  hexdump(sccp_gt_buf, sizeof(sccp_gt_buf));
  fprintf(stderr, "Decoded SCCP GT [%u]: %s\n", sccp_gt_len, sccp_gt_dec);
  encode_called_party(sccp_gt_dec, sccp_gt_len, sccp_gt_encoded_buf, &sccp_gt_len);
  fprintf(stderr, "Encoded SCCP GT [%u]:\n", sccp_gt_len);
  hexdump(sccp_gt_encoded_buf, sccp_gt_len);


  return 0;
}
