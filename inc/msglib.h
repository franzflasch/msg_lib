#ifndef MSG_LIB_H_
#define MSG_LIB_H_

#include <stdint.h>

#define MSG_CRC_LOC 0
#define MSG_TYPE_LOC (sizeof(uint16_t))
#define MSG_ID_LOC (MSG_TYPE_LOC+sizeof(uint8_t))
#define MSG_ADDR_LOC (MSG_ID_LOC+sizeof(uint8_t))
#define MSG_LEN_LOC (MSG_ADDR_LOC+sizeof(uint16_t))
#define MSG_PAYLOAD_LOC (MSG_LEN_LOC+sizeof(uint16_t))


#define MSG_LIB_BUF_SIZE_TO_ADD MSG_PAYLOAD_LOC

#define MSG_LIB_INFO_TYPE 0
#define MSG_LIB_INFO_ID 1
#define MSG_LIB_INFO_ADDR 2
#define MSG_LIB_INFO_LEN 3

#define MSG_LIB_MSGTYPE_WRITE 0
#define MSG_LIB_MSGTYPE_READ 1

void msglib_swap_endianess(uint8_t *msg);

uint16_t msglib_encode_write(uint8_t msg_id,
					   	     uint16_t addr,
							 uint8_t *outbuf,
							 uint16_t outbuf_size,
							 void *inbuf,
							 uint16_t inbuf_size,
							 uint16_t len,
							 uint8_t swap_endianess);

uint16_t msglib_encode_read(uint8_t msg_id,
					   	     uint16_t addr,
							 uint8_t *outbuf,
							 uint16_t outbuf_size,
							 uint16_t inbuf_size,
							 uint16_t len,
							 uint16_t *ret_expected_size_to_copy,
							 uint8_t swap_endianess);

int16_t msglib_decode(void *outbuf, uint16_t outbuf_size, uint8_t *msg, uint8_t swap_endianess);
int16_t msglib_get_info(uint8_t *msg, uint16_t what);

#endif /* MSG_LIB_H_ */
