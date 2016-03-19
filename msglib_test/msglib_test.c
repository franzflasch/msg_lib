#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <OMM_machine_common.h>
#include <msglib.h>

#include <micro_unit.h>

typedef struct __attribute__((__packed__)) shared_mem_test_s
{
	uint8_t w;
	uint16_t x;
	uint8_t y;
	uint8_t z;

}shared_mem_test_t;

static uint8_t spi_message[sizeof(shared_mem_test_t)+MSG_LIB_BUF_SIZE_TO_ADD];


MICRO_UNIT_TEST(test_encode_decode_write_full)
{
	uint16_t bytes_written;
	int16_t msg_type;

	shared_mem_test_t test_shared_encode = { 1, 2, 3, 4 };
	shared_mem_test_t test_shared_decode = { 0, 0, 0, 0 };

	memset(spi_message, 0, sizeof(spi_message));

    bytes_written = msglib_encode_write(42, offsetof(shared_mem_test_t, w), spi_message, sizeof(spi_message), &test_shared_encode, sizeof(test_shared_encode), 0, 0);
    MICRO_UNIT_ASSERT_INT_EQ(13, bytes_written);

	/* Now decode the message and write the payload into the second shared mem struct */
	msg_type = msglib_decode(&test_shared_decode, sizeof(test_shared_decode), spi_message, 0);

	MICRO_UNIT_ASSERT_INT_EQ(MSG_LIB_MSGTYPE_WRITE , msg_type);

	MICRO_UNIT_ASSERT_INT_EQ(1, test_shared_decode.w);
	MICRO_UNIT_ASSERT_INT_EQ(2, test_shared_decode.x);
	MICRO_UNIT_ASSERT_INT_EQ(3, test_shared_decode.y);
	MICRO_UNIT_ASSERT_INT_EQ(4, test_shared_decode.z);
}

MICRO_UNIT_TEST(test_encode_decode_write_partial)
{
	uint16_t bytes_written;
	int16_t msg_type;

	shared_mem_test_t test_shared_encode = { 1, 2, 3, 4 };
	shared_mem_test_t test_shared_decode = { 0, 0, 0, 0 };

	memset(spi_message, 0, sizeof(spi_message));

    bytes_written = msglib_encode_write(42, offsetof(shared_mem_test_t, y), spi_message, sizeof(spi_message), &test_shared_encode, sizeof(test_shared_encode), sizeof(test_shared_encode.y), 0);
    MICRO_UNIT_ASSERT_INT_EQ(9, bytes_written);

	/* Now decode the message and write the payload into the second shared mem struct */
	msg_type = msglib_decode(&test_shared_decode, sizeof(test_shared_decode), spi_message, 0);

	MICRO_UNIT_ASSERT_INT_EQ(MSG_LIB_MSGTYPE_WRITE , msg_type);

	MICRO_UNIT_ASSERT_INT_EQ(0, test_shared_decode.w);
	MICRO_UNIT_ASSERT_INT_EQ(0, test_shared_decode.x);
	MICRO_UNIT_ASSERT_INT_EQ(3, test_shared_decode.y);
	MICRO_UNIT_ASSERT_INT_EQ(0, test_shared_decode.z);
}

MICRO_UNIT_TEST(test_encode_decode_crc_error)
{
	uint16_t bytes_written;
	int16_t msg_type;

	shared_mem_test_t test_shared_encode = { 1, 2, 3, 4 };
	shared_mem_test_t test_shared_decode = { 0, 0, 0, 0 };

	memset(spi_message, 0, sizeof(spi_message));

	/* Second testcase CRC error */
	bytes_written = msglib_encode_write(42, offsetof(shared_mem_test_t, y), spi_message, sizeof(spi_message), &test_shared_encode, sizeof(test_shared_encode), 0, 0);
	MICRO_UNIT_ASSERT_INT_EQ(10, bytes_written);

	/* Produce some crc error */
	spi_message[8] = 122;
	msg_type = msglib_decode(&test_shared_decode, sizeof(test_shared_decode), spi_message, 0);

	MICRO_UNIT_ASSERT_INT_EQ(-1, msg_type);
}

MICRO_UNIT_TEST(test_encode_decode_message_handling)
{
	uint16_t bytes_written;
	int16_t msg_type;
	uint16_t dummy_bytes;

	uint16_t msg_id = 0;
	uint16_t addr = 0;
	uint16_t msg_len = 0;

	shared_mem_test_t test_shared_master = { 0, 0, 0, 0 };
	shared_mem_test_t test_shared_slave = { 0x1, 0x2233, 0x44, 0x55 };

	memset(spi_message, 0, sizeof(spi_message));

	/* This will be called from the master */
	bytes_written = msglib_encode_read(42, offsetof(shared_mem_test_t, y), spi_message, sizeof(spi_message), sizeof(test_shared_master), 1, &dummy_bytes, 0);

	/* This will be called from the slave */
	if(msglib_decode(&test_shared_slave, sizeof(test_shared_slave), spi_message, 0) == MSG_LIB_MSGTYPE_READ)
	{
		/* OK got read message encode the return message in the buffer */
		msg_id = msglib_get_info(spi_message, MSG_LIB_INFO_ID);
		addr = msglib_get_info(spi_message, MSG_LIB_INFO_ADDR);
		msg_len = msglib_get_info(spi_message, MSG_LIB_INFO_LEN);

		MICRO_UNIT_ASSERT_INT_EQ(42, msg_id);
		MICRO_UNIT_ASSERT_INT_EQ(3, offsetof(shared_mem_test_t, y));
		MICRO_UNIT_ASSERT_INT_EQ(1, msg_len);

		bytes_written = msglib_encode_write(msg_id, addr, spi_message, sizeof(spi_message), &test_shared_slave, sizeof(test_shared_slave), msg_len, 0);
		MICRO_UNIT_ASSERT_INT_EQ(9, bytes_written);

		/* This will be called from the master again */
		msg_type = msglib_decode(&test_shared_master, sizeof(test_shared_master), spi_message, 0);

		MICRO_UNIT_ASSERT_INT_EQ(MSG_LIB_MSGTYPE_WRITE , msg_type);

		MICRO_UNIT_ASSERT_INT_EQ(0, test_shared_master.w);
		MICRO_UNIT_ASSERT_INT_EQ(0, test_shared_master.x);
		MICRO_UNIT_ASSERT_INT_EQ(0x44, test_shared_master.y);
		MICRO_UNIT_ASSERT_INT_EQ(0, test_shared_master.z);
	}
	else
	{
		MICRO_UNIT_FAIL("Error MSG_LIB_MSGTYPE_READ expected");
	}
}

MICRO_UNIT_TEST_SUITE(test_suite)
{
    MICRO_UNIT_RUN_TEST(test_encode_decode_write_full);
    MICRO_UNIT_RUN_TEST(test_encode_decode_write_partial);
    MICRO_UNIT_RUN_TEST(test_encode_decode_crc_error);
    MICRO_UNIT_RUN_TEST(test_encode_decode_message_handling);
}


int __attribute__((weak)) main (void)
{
	OMM_machine_t *machine = machine_setup();

    while (1)
    {
    	printf("\r\nStarting Test for %s\r\n", machine->name);

    	MICRO_UNIT_RUN_SUITE(test_suite);
    	MICRO_UNIT_REPORT();

    	while(1)
    	{
    		OMM_busy_delay(500);
    	}
    }
}
