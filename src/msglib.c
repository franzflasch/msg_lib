#include <msglib.h>
#include <crc.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Message will be constructed this way:
 * |CRC16|MSG_TYPE|MSG_ID|ADDRH|ADDRL|LENGTHH|LENGTHL|DATA0|...|DATAN|
 *
 * */

#ifdef __linux__
#include <byteswap.h>

void msglib_swap_endianess(uint8_t *msg)
{
	uint16_t *tmp_u16;

	/* Addr, len have to be swapped */
	tmp_u16 = (uint16_t *) &msg[MSG_ADDR_LOC];
	*tmp_u16 = __bswap_16(*tmp_u16);

	tmp_u16 = (uint16_t *) &msg[MSG_LEN_LOC];
	*tmp_u16 = __bswap_16(*tmp_u16);
}
void msglib_swap_endianess_crc(uint8_t *msg)
{
	uint16_t *tmp_u16;
	tmp_u16 = (uint16_t *) &msg[MSG_CRC_LOC];
	*tmp_u16 = __bswap_16(*tmp_u16);
}

#else
void msglib_swap_endianess(uint8_t *msg)
{
	return;
}
void msglib_swap_endianess_crc(uint8_t *msg)
{
	return;
}
#endif

static void msglib_add_crc(uint8_t *outbuf,
						uint16_t len,
						uint8_t swap_endianess)
{
	uint16_t crc = 0;
	uint8_t *tmp_buf = NULL;

	/* Now add the CRC */
	crc = crc16_ccitt(&outbuf[MSG_TYPE_LOC], (len+(MSG_LIB_BUF_SIZE_TO_ADD-2)));

	tmp_buf = (uint8_t *) &crc;
	memcpy(&outbuf[MSG_CRC_LOC], &tmp_buf[0], sizeof(crc));

	if(swap_endianess)
	{
		msglib_swap_endianess_crc(outbuf);
	}
}

uint16_t message_encode_header(uint8_t msg_type,
							  uint8_t msg_id,
							  uint16_t addr,
							  uint8_t *outbuf,
							  uint16_t outbuf_size,
							  uint16_t inbuf_size,
							  uint16_t len)
{
	uint8_t *tmp_buf = NULL; //(uint8_t *)inbuf;
	uint16_t size_to_copy = 0;

	/* Calculate the acrtual size to copy */
	if(inbuf_size != 0)
		size_to_copy = inbuf_size - addr;

	if(size_to_copy > outbuf_size )
		return 0;

	if((len > 0) && (len<=size_to_copy))
		size_to_copy = len;

	/* Check if size_to_copy is smaller than the output buffer, +MSG_LIB_BUF_SIZE_TO_ADD because of the type + id + addr + len + CRC */
	if((size_to_copy+MSG_LIB_BUF_SIZE_TO_ADD) > outbuf_size)
		return -1;

	outbuf[MSG_TYPE_LOC] = msg_type;
	outbuf[MSG_ID_LOC] = msg_id;

	tmp_buf = (uint8_t *) &addr;
	memcpy(&outbuf[MSG_ADDR_LOC], &tmp_buf[0], sizeof(addr));

	tmp_buf = (uint8_t *) &size_to_copy;
	memcpy(&outbuf[MSG_LEN_LOC], &tmp_buf[0], sizeof(size_to_copy));

	return size_to_copy;
}

uint16_t msglib_encode_write(uint8_t msg_id,
					   	     uint16_t addr,
							 uint8_t *outbuf,
							 uint16_t outbuf_size,
							 void *inbuf,
							 uint16_t inbuf_size,
							 uint16_t len,
							 uint8_t swap_endianess)
{
	uint8_t *tmp_buf = NULL; //(uint8_t *)inbuf;
	uint16_t size_to_copy = 0;

	size_to_copy = message_encode_header(MSG_LIB_MSGTYPE_WRITE, msg_id, addr, outbuf, outbuf_size, inbuf_size, len);

	if(size_to_copy == 0)
	{
		return size_to_copy;
	}

	if(swap_endianess)
	{
		msglib_swap_endianess(outbuf);
	}

	tmp_buf = (uint8_t *) inbuf;
	memcpy(&outbuf[MSG_PAYLOAD_LOC], &tmp_buf[addr], size_to_copy);

	msglib_add_crc(outbuf, size_to_copy, swap_endianess);

	return size_to_copy + MSG_LIB_BUF_SIZE_TO_ADD;
}

uint16_t msglib_encode_read(uint8_t msg_id,
					   	     uint16_t addr,
							 uint8_t *outbuf,
							 uint16_t outbuf_size,
							 uint16_t inbuf_size,
							 uint16_t len,
							 uint16_t *ret_expected_size_to_copy,
							 uint8_t swap_endianess)
{
	uint16_t size_to_copy = 0;

	size_to_copy = message_encode_header(MSG_LIB_MSGTYPE_READ, msg_id, addr, outbuf, outbuf_size, inbuf_size, len);

	if(size_to_copy == 0 )
	{
		return size_to_copy;
	}

	if(swap_endianess)
	{
		msglib_swap_endianess(outbuf);
	}

	msglib_add_crc(outbuf, 0, swap_endianess);

	*ret_expected_size_to_copy = size_to_copy + MSG_LIB_BUF_SIZE_TO_ADD;

	return MSG_LIB_BUF_SIZE_TO_ADD;
}

int16_t msglib_decode(void *outbuf, uint16_t outbuf_size, uint8_t *msg, uint8_t swap_endianess)
{
	/* Prepare all variables we want to extract from the message */
	uint8_t *tmp_buf;
	uint16_t addr = 0;
	uint16_t len = 0;
	uint16_t crc_in = 0;
	uint16_t crc = 0;

	uint8_t msg_type = 0;

	/* we need to swap to get the right header information */
	if(swap_endianess)
	{
		msglib_swap_endianess(msg);
		msglib_swap_endianess_crc(msg);
	}

	msg_type = msglib_get_info(msg, MSG_LIB_INFO_TYPE);
	addr = msglib_get_info(msg, MSG_LIB_INFO_ADDR);
	len = msglib_get_info(msg, MSG_LIB_INFO_LEN);

	/* Get crc from and of message */
	memcpy(&crc_in, &msg[MSG_CRC_LOC], sizeof(crc_in));

	/* now we need to swap back for the right crc calculation */
	if(swap_endianess)
	{
		msglib_swap_endianess(msg);
		msglib_swap_endianess_crc(msg);
	}

	if(msg_type == MSG_LIB_MSGTYPE_WRITE)
	{
		crc = crc16_ccitt(&msg[MSG_TYPE_LOC], len+((MSG_LIB_BUF_SIZE_TO_ADD-2)));
	}
	else if(msg_type == MSG_LIB_MSGTYPE_READ)
	{
		crc = crc16_ccitt(&msg[MSG_TYPE_LOC], (MSG_LIB_BUF_SIZE_TO_ADD-2));
	}

	/* OK swap back again here */
	if(swap_endianess)
	{
		msglib_swap_endianess(msg);
		msglib_swap_endianess_crc(msg);
	}


	//printf("addr: 0x%04x len: 0x%04x crc_in: 0x%04x \r\n", addr, len, crc_in);

	/* Check CRC */
	if(crc != crc_in)
	{
		printf("CRC error: %x %x!\r\n", crc, crc_in);
		return -1;
	}

	/* Sanity check */
	if(len>outbuf_size)
	{
		printf("Something wrong with message size!\r\n");
		return -1;
	}

	if(msg_type == MSG_LIB_MSGTYPE_READ)
		return msg_type;

	tmp_buf = outbuf;
	memcpy(&tmp_buf[addr], &msg[MSG_PAYLOAD_LOC], len);

	return msg_type;
}

int16_t msglib_get_info(uint8_t *msg, uint16_t what)
{
	uint16_t addr = 0;
	uint16_t len = 0;

	switch(what)
	{
		case MSG_LIB_INFO_TYPE:
			return msg[MSG_TYPE_LOC];
		break;
		case MSG_LIB_INFO_ID:
			return msg[MSG_ID_LOC];
		break;
		case MSG_LIB_INFO_ADDR:
			/* Get addr from message */
			memcpy(&addr, &msg[MSG_ADDR_LOC], sizeof(addr));
			return addr;
			break;
		case MSG_LIB_INFO_LEN:
			/* Get len from and of message */
			memcpy(&len, &msg[MSG_LEN_LOC], sizeof(len));
			return len;
		break;
		default:
			return -1;
	}

	return -1;
}
