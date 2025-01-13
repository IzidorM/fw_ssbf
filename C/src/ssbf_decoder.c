#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ssbf.h"
#include "ssbf_internal.h"
#include "ssbf_common.h"

#include "monocypher.h"

#ifdef UNIT_TESTS
#define STATIC
#else
#define STATIC static
#endif

STATIC enum ssbf_errors ssbf_decode_block_header(
	uint8_t *input_data,
	size_t input_data_size,
	struct ssbf_payload_block_header *h)
{
	if (sizeof(struct ssbf_payload_block_header) > input_data_size)
	{
		return SSBF_NOT_ENOUGHT_DATA;
	}

	uint8_t hcs = bsd_checksum8(input_data, 
				    sizeof(struct ssbf_payload_block_header) - 1);

	if (hcs != input_data[sizeof(struct ssbf_payload_block_header) - 1])
	{
		return SSBF_GENERIC_ERROR;
	}

	memcpy(h, input_data, sizeof(struct ssbf_payload_block_header));

	return SSBF_NO_ERROR;
}

STATIC enum ssbf_errors ssbf_decode_block(uint8_t *key_block,
				struct ssbf_payload_block_header *block_header,
				uint8_t *input_data,
				uint8_t *output_data,
				size_t output_data_max_mem_size,
				size_t *output_data_actual_size)
{

	uint8_t tmp_nonce[ 24];

	memset(tmp_nonce, 0, sizeof(tmp_nonce));
	tmp_nonce[0] = block_header->block_number & 0xff;
	tmp_nonce[1] = (block_header->block_number >> 8) & 0xff;


	// check checksum
	uint16_t bcs = bsd_checksum16(input_data, block_header->compressed_size);
	if (bcs != block_header->data_checksum)
	{
		return SSBF_CHECKSUM_FAILED;
	}

	ssbf_crypto_inplace_chacha20(key_block,
				     tmp_nonce, // use block_number as a nonce
				     input_data,
				     block_header->compressed_size,
				     &block_header->flags);


	if (block_header->flags & BHF_BLOCK_COMPRESSED)
	{
		*output_data_actual_size = 
			sdf_decompress_lz4(input_data,
					   output_data,
					   block_header->compressed_size,
					   output_data_max_mem_size);


		// TODO: Should we check that it is not bigger that 
		// max_block_size aswell?
		if (0 >= *output_data_actual_size)
		{
			return SSBF_COMPRESSION_FAILED;
		}
	}

	return SSBF_NO_ERROR;
}

STATIC enum ssbf_errors ssbf_decode_data_from_blocks(uint8_t *key_block,
					 size_t max_block_size,
					 uint8_t *input_data_start,
					 size_t input_data_size,
					 uint8_t *output_data_start,				
					 size_t output_data_max_size,
					 size_t *actual_output_data_size)
{
	(void) max_block_size;

	enum ssbf_errors r = SSBF_NO_ERROR;
	uint8_t *input_data_current_p = input_data_start;
	uint8_t *output_data_current_p = output_data_start;
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

		input_data_current_p += sizeof(struct ssbf_payload_block_header);


		int32_t output_data_left = output_data_max_size 
			- (output_data_current_p - output_data_start);

		size_t block_output_data_size = 0;

		r = ssbf_decode_block(key_block,
				      &h,
				      input_data_current_p,
				      output_data_current_p,
				      output_data_left,
				      &block_output_data_size);

		input_data_current_p += h.compressed_size;
		output_data_current_p += block_output_data_size;


		*actual_output_data_size += block_output_data_size;

		//printf("%i: %i -> %zu\n", h.block_number,
		//       h.compressed_size,
		//       block_output_data_size);
	}

	return r;
}

enum ssbf_errors ssbf_decode_data(uint8_t *key_main, //[32],
				  uint8_t *input_data_start,
				  size_t input_data_size,
				  uint8_t *output_data_start,				
				  size_t output_data_max_size,
				  size_t *actual_output_data_size)
{

	(void) input_data_size;

	const uint16_t full_header_hash_mac_size = 16;

	uint8_t *input_data_current_p = input_data_start;

	// main header
	struct ssbf_main_header mh;
	memcpy(&mh, input_data_current_p, sizeof(struct ssbf_main_header));
	input_data_current_p += sizeof(struct ssbf_main_header);

	uint16_t cs = bsd_checksum8(
		(uint8_t *) &mh, sizeof(struct ssbf_main_header)-1);
	if (cs != mh.header_checksum)
	{
		return SSBF_CHECKSUM_FAILED;
	}


	// crypto header
	struct ssbf_encryption_header ch;
	memcpy(&ch, input_data_current_p, sizeof(struct ssbf_encryption_header));
	input_data_current_p += sizeof(struct ssbf_encryption_header);

	size_t full_header_size = 
		+ sizeof(struct ssbf_main_header)
		+ sizeof(struct ssbf_encryption_header)
		+ ch.encrypted_header_size
		+ full_header_hash_mac_size; // hash size

	uint8_t *mac_addr_p = input_data_start 
		+ full_header_size - full_header_hash_mac_size;


	int r = crypto_aead_unlock(input_data_current_p, 
				   mac_addr_p, 
				   key_main, ch.nonce,
				   input_data_start, 
				   sizeof(struct ssbf_main_header)
				   + sizeof(struct ssbf_encryption_header),
				   input_data_current_p,
				   ch.encrypted_header_size);
	if (r)
	{
		return SSBF_DECRYPTION_FAILED;
	}

	uint8_t key_data[32];
	memcpy(key_data, input_data_current_p, ch.encryption_payload_size);
	input_data_current_p += ch.encryption_payload_size;


	struct ssbf_meta_header meta_h;

	memcpy(&meta_h, input_data_current_p, sizeof(struct ssbf_meta_header));
	input_data_current_p += sizeof(struct ssbf_meta_header);

	uint8_t meta_payload_data[meta_h.payload_size];

	memcpy(meta_payload_data, input_data_current_p, meta_h.payload_size);
	input_data_current_p += meta_h.payload_size;

	struct ssbf_data_header data_h;

	memcpy(&data_h, input_data_current_p, sizeof(struct ssbf_data_header));
	input_data_current_p += sizeof(struct ssbf_data_header);

	// skip the mac
	input_data_current_p += full_header_hash_mac_size; // mac size

	// if all is ok, output_data_current_p points now to start of the first block
	if (input_data_current_p != (input_data_start + full_header_size))
	{
		printf("output data error 1\n");
	}

	if (input_data_current_p + mh.blocks_sum_size != (input_data_start + input_data_size))
	{
		printf("output data error 2\n");
	}

	enum ssbf_errors e = ssbf_decode_data_from_blocks(
		key_data,
		data_h.max_uncompressed_block_size,
		input_data_current_p,
		mh.blocks_sum_size,
		output_data_start,				
		output_data_max_size,
		actual_output_data_size);

	return e;
}
