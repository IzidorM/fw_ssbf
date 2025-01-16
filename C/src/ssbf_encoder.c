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


STATIC size_t ssbf_encode_block(uint8_t *key_data,
				uint8_t *output_mem,
				uint8_t *input_data_start, 
				size_t input_data_size,
				uint16_t block_number,
				uint8_t input_flags)
{

	uint8_t *output_mem_data = output_mem
		+ sizeof(struct ssbf_payload_block_header);

	struct ssbf_payload_block_header *block_working_mem_header = 
		(struct ssbf_payload_block_header *) output_mem;

	block_working_mem_header->flags = input_flags;

	memset(block_working_mem_header, 0, 
	       sizeof(struct ssbf_payload_block_header));

	int32_t cs = ssbf_compress_lz4(
		input_data_start, output_mem_data,
		(uint32_t) input_data_size,
		&block_working_mem_header->flags);

	uint8_t tmp_nonce[ 24];
	memset(tmp_nonce, 0, sizeof(tmp_nonce));
	tmp_nonce[0] = block_number & 0xff;
	tmp_nonce[1] = (block_number >> 8) & 0xff;

	ssbf_crypto_inplace_chacha20(key_data,
				     tmp_nonce, // use block_number as a nonce
				     output_mem_data,
				     cs,
				     &block_working_mem_header->flags);

	block_working_mem_header->block_number = block_number;
	block_working_mem_header->compressed_size = (uint16_t) cs;
	block_working_mem_header->data_checksum = bsd_checksum16(
		output_mem_data, cs);

	block_working_mem_header->header_checksum = bsd_checksum8(
		(uint8_t *) block_working_mem_header,
		sizeof(struct ssbf_payload_block_header)-1);

	return block_working_mem_header->compressed_size 
		+ sizeof(struct ssbf_payload_block_header);
}

STATIC void ssbf_encode_data_to_blocks(uint8_t *key_data,
				size_t max_block_size,
				uint8_t *input_data_start,
				size_t input_data_size,
				uint8_t *output_data_start,				
				size_t output_data_max_size,
				size_t *actual_output_data_size)
{

	// TODO: Check for output data out of bounds error
	(void) output_data_max_size;

	*actual_output_data_size = 0;

	uint8_t *input_data_current_p = input_data_start;
	uint8_t *output_data_current_p = output_data_start;

	uint16_t block_cnt = 0; 

	int32_t input_data_size_minus_last_block = 
		input_data_size - max_block_size;

	size_t encoded_block_size_with_header = 0;

	int32_t i;
	for (i = 0; input_data_size_minus_last_block > i; i += max_block_size)
	{
		encoded_block_size_with_header = 
			ssbf_encode_block(
				key_data,
				output_data_current_p,
				input_data_current_p,
				max_block_size,
				block_cnt, 0); 

		input_data_current_p += max_block_size;
		output_data_current_p += encoded_block_size_with_header;
		block_cnt += 1;
	}

	// last block
	uint32_t data_left = input_data_size - i;

	encoded_block_size_with_header = 
		ssbf_encode_block(
			key_data,
			output_data_current_p,
			input_data_current_p,
			data_left,
			block_cnt, BHF_LAST_BLOCK); 

	*actual_output_data_size = encoded_block_size_with_header 
		+ (output_data_current_p - output_data_start);
}

void ssbf_encode_data(uint8_t *key_main, //[32],
		      uint8_t *key_main_nonce, //[24]
		      uint8_t *key_data, //[32]
		      uint16_t meta_data_id,
		      uint8_t *meta_payload_data,
		      uint16_t meta_data_payload_size,
		      size_t max_block_size,
		      uint8_t *input_data_start,
		      size_t input_data_size,
		      uint8_t *output_data_start,				
		      size_t output_data_max_size,
		      size_t *actual_output_data_size)
{

	const uint16_t encryption_payload_size = 32;
	const uint16_t full_header_hash_mac_size = 16;

	// encode data to blocks
	size_t full_header_size = 
		+ sizeof(struct ssbf_main_header)
		+ sizeof(struct ssbf_encryption_header)
		+ encryption_payload_size
		+ sizeof(struct ssbf_meta_header)
		+ meta_data_payload_size
		+ sizeof(struct ssbf_data_header)
		+ full_header_hash_mac_size; // hash size

	ssbf_encode_data_to_blocks(key_data,
				   max_block_size,
				   input_data_start,
				   input_data_size,
				   output_data_start + full_header_size,
				   output_data_max_size,
				   actual_output_data_size);


	uint8_t *output_data_current_p = output_data_start;

	// main header
	struct ssbf_main_header mh = {
		.ssbf_magic_number = SSBFv1_MAGIC_NUMBER,
		.flags = SSBF_MAIN_HEADE_FLAG_USE_META_EXTENSION 
		| SSBF_MAIN_HEADE_FLAG_USE_ENCRYPTION_EXTENSION,
		.blocks_sum_size = *actual_output_data_size,
		.hashed_data_size = full_header_size - full_header_hash_mac_size,
		.header_checksum = 0,
	};

	mh.header_checksum = bsd_checksum8(
		(uint8_t *) &mh, sizeof(struct ssbf_main_header)-1);

	memcpy(output_data_current_p, &mh, sizeof(struct ssbf_main_header));
	output_data_current_p += sizeof(struct ssbf_main_header);

	// crypto header
	struct ssbf_encryption_header ch = {
		.encryption_payload_size = encryption_payload_size,
		.encrypted_header_size = encryption_payload_size
		+ sizeof(struct ssbf_meta_header)
		+ meta_data_payload_size
		+ sizeof(struct ssbf_data_header),
		.flags = SSBF_ENCRYPTION_HEADER_FLAG_USE_POLY1305
		 | SSBF_ENCRYPTION_HEADER_FLAG_USE_CHACHA20,
	};

	memcpy(ch.nonce, key_main_nonce, 24);

	ch.header_checksum = bsd_checksum8(
		(uint8_t *) &ch, sizeof(struct ssbf_encryption_header)-1);

	memcpy(output_data_current_p, &ch, sizeof(struct ssbf_encryption_header));
	output_data_current_p += sizeof(struct ssbf_encryption_header);

	uint8_t *encrypt_data_from_here = output_data_current_p;

	memcpy(output_data_current_p, key_data, ch.encryption_payload_size);
	output_data_current_p += ch.encryption_payload_size;



	struct ssbf_meta_header meta_h = {
		.meta_data_id = meta_data_id,
		.payload_size = meta_data_payload_size,
	};

	memcpy(output_data_current_p, &meta_h, sizeof(struct ssbf_meta_header));
	output_data_current_p += sizeof(struct ssbf_meta_header);

	memcpy(output_data_current_p, meta_payload_data, meta_h.payload_size);
	output_data_current_p += meta_h.payload_size;



	struct ssbf_data_header data_h = {
		.full_data_size_uncompressed = input_data_size,
		.max_uncompressed_block_size = max_block_size, //is this with or without header?
		.flags = 0, // we use default checksum (bsd 16)
		.reserved = 0,
		.full_data_checksum = bsd_checksum16(input_data_start,
						     input_data_size),
	};

	memcpy(output_data_current_p, &data_h, sizeof(struct ssbf_data_header));
	output_data_current_p += sizeof(struct ssbf_data_header);


	// Calculate header hash and encrypt part of header

	crypto_aead_lock(encrypt_data_from_here, output_data_current_p,
			 key_main, key_main_nonce, 
			 output_data_start, 
			 sizeof(struct ssbf_main_header)
			 + sizeof(struct ssbf_encryption_header),
			 encrypt_data_from_here, 
			 ch.encrypted_header_size);

	output_data_current_p += full_header_hash_mac_size; // mac size

	// if all is ok, output_data_current_p points now to start of the first block
	if (output_data_current_p != (output_data_start + full_header_size))
	{
		printf("output data error\n");
	}

	*actual_output_data_size += full_header_size;
}
