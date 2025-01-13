#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ssbf.h"
#include "ssbf_internal.h"
#include "ssbf_common.h"

#ifdef UNIT_TESTS
#define STATIC
#else
#define STATIC static
#endif


STATIC enum ssbf_errors ssbf_explain_blocks( uint8_t *input_data_start,
					     size_t input_data_size)
{
	enum ssbf_errors r = SSBF_NO_ERROR;
	uint8_t *input_data_current_p = input_data_start;

	struct ssbf_payload_block_header h;

	while((input_data_start + input_data_size) > input_data_current_p)
	{
		int32_t input_data_left = input_data_size 
			- (input_data_current_p - input_data_start);
		r = ssbf_decode_block_header(input_data_current_p,
					     input_data_left,
					     &h);
		if (SSBF_NO_ERROR != r)
		{
			return r;
		}

		input_data_current_p += 
			sizeof(struct ssbf_payload_block_header)
			+ h.compressed_size;

		printf("  ");
		if (h.flags & BHF_LAST_BLOCK)
		{
			printf("last ");
		}
		printf("block %i of size %i found, ", h.block_number,
		       h.compressed_size);

		if (h.flags & BHF_BLOCK_COMPRESSED)
		{
			printf("compressed, ");
		}
		if (h.flags & BHF_BLOCK_ENCRYPTED)
		{
			printf(" encrypted");
		}
		printf("\n");
	}

	return r;
}

enum ssbf_errors ssbf_explain( uint8_t *input_data_start,
			       size_t input_data_size)
{
	(void) input_data_size;

	const uint16_t full_header_hash_mac_size = 16;

	uint8_t *input_data_current_p = input_data_start;

	// copy main header data from input data
	struct ssbf_main_header mh;
	memcpy(&mh, input_data_current_p, sizeof(struct ssbf_main_header));
	input_data_current_p += sizeof(struct ssbf_main_header);

	uint8_t cs = bsd_checksum8(
		(uint8_t *) &mh, sizeof(struct ssbf_main_header)-1);
	if (cs != mh.header_checksum)
	{
		return SSBF_CHECKSUM_FAILED;
	}

	printf("\nMain header:\n");
	printf("  ssbf_magic_number: 0x%x\n", mh.ssbf_magic_number);
	printf("  blocks_sum_size: %i\n", mh.blocks_sum_size);
	printf("  hashed_data_size: %i\n", mh.hashed_data_size);
	printf("  flags (0x%x):\n", mh.flags);
	if (SSBF_MAIN_HEADE_FLAG_USE_META_EXTENSION & mh.flags)
	{
		printf("    SSBF_MAIN_HEADE_FLAG_USE_META_EXTENSION\n");
	}
	if (SSBF_MAIN_HEADE_FLAG_USE_ENCRYPTION_EXTENSION & mh.flags)
	{
		printf("    SSBF_MAIN_HEADE_FLAG_USE_ENCRYPTION_EXTENSION\n");
	}
	printf("  bsd checksum8: %i\n", mh.header_checksum);

	// copy encryption header data from input data
	struct ssbf_encryption_header ch;
	memcpy(&ch, input_data_current_p, sizeof(struct ssbf_encryption_header));
	input_data_current_p += sizeof(struct ssbf_encryption_header);

	cs = bsd_checksum8(
		(uint8_t *) &ch, sizeof(struct ssbf_encryption_header)-1);
	if (cs != ch.header_checksum)
	{
		return SSBF_CHECKSUM_FAILED;
	}

	printf("\nEncryption header:");
	printf("  encryption_payload_size: %i\n", ch.encryption_payload_size);
	printf("  encrypted_header_size: %i\n", ch.encrypted_header_size);
	printf("  flags (0x%x):\n", ch.encrypted_header_size);
	if (SSBF_ENCRYPTION_HEADER_FLAG_USE_POLY1305 & ch.flags)
	{
		printf("    SSBF_ENCRYPTION_HEADER_FLAG_USE_POLY1305\n");
	}
	if (SSBF_ENCRYPTION_HEADER_FLAG_USE_CHACHA20 & ch.flags)
	{
		printf("    SSBF_ENCRYPTION_HEADER_FLAG_USE_CHACHA20\n");
	}
	printf("  bsd checksum8: %i\n", ch.header_checksum);

	printf("\nrest of the header (%i bytes) is encrypted\n", 
	       ch.encrypted_header_size);

	input_data_current_p += ch.encrypted_header_size;

	printf("\nMAC (header): ");
	for (uint32_t i = 0; i < full_header_hash_mac_size; i++)
	{
		printf("%02x ", input_data_current_p[i]);
	}
	printf("\n");

	// skip the mac
	input_data_current_p += full_header_hash_mac_size; // mac size

	if (input_data_current_p + mh.blocks_sum_size 
	    != (input_data_start + input_data_size))
	{
		printf("parsing error\n");
		return 0;
	}

	printf("\nBlocks: ");
	return ssbf_explain_blocks( input_data_current_p, 
				    mh.blocks_sum_size);
}
