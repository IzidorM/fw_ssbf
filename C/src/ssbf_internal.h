#ifndef SSBF_INTERNAL_H
#define SSBF_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>

#include "ssbf.h"

enum block_header_flags {
	BHF_LAST_BLOCK = 1,
	BHF_BLOCK_COMPRESSED = 2,
	BHF_BLOCK_ENCRYPTED = 4,
};

struct ssbf_main_header {
	uint32_t ssbf_magic_number;
	uint32_t blocks_sum_size;
        uint16_t hashed_data_size;
        uint8_t flags;
        uint8_t header_checksum;
};

struct ssbf_encryption_header {
        uint8_t nonce[24];
        uint16_t encryption_payload_size;
	uint16_t encrypted_header_size;
        uint8_t flags;
        uint8_t header_checksum;
};

struct ssbf_meta_header {
     uint16_t meta_data_id;
     uint16_t payload_size;
};

struct ssbf_data_header {
        uint32_t full_data_size_uncompressed;
        uint16_t max_uncompressed_block_size;
        uint8_t flags;
        uint8_t reserved;
        uint32_t full_data_checksum;
};

struct ssbf_payload_block_header {
        uint16_t block_number;
        uint16_t compressed_size; //TODO: rename to data_size
        uint16_t data_checksum;
        uint8_t flags;
        uint8_t header_checksum;
};

#ifdef UNIT_TESTS
size_t ssbf_encode_block(uint8_t *key_data,
			 uint8_t *output_mem,
			 uint8_t *input_data_start, 
			 size_t input_data_size,
			 uint16_t block_number,
			 uint8_t input_flags);

void ssbf_encode_data_to_blocks(uint8_t *key_data,
				size_t max_block_size,
				uint8_t *input_data_start,
				size_t input_data_size,
				uint8_t *output_data_start,				
				size_t output_data_max_size,
				size_t *actual_output_data_size);


enum ssbf_errors ssbf_decode_block_header(
	uint8_t *input_data,
	size_t input_data_size,
	struct ssbf_payload_block_header *h);


enum ssbf_errors ssbf_decode_block(uint8_t *block_key,
				   struct ssbf_payload_block_header *block_header,
				   uint8_t *input_data,
				   uint8_t *output_data,
				   size_t output_data_max_mem_size,
				   size_t *output_data_actual_size);

enum ssbf_errors ssbf_decode_data_from_blocks(uint8_t *block_key,
					 size_t max_block_size,
					 uint8_t *input_data_start,
					 size_t input_data_size,
					 uint8_t *output_data_start,				
					 size_t output_data_max_size,
					      size_t *actual_output_data_size);

enum ssbf_errors ssbf_decode_data(uint8_t *key_main, //[32],
				  uint8_t *input_data_start,
				  size_t input_data_size,
				  uint8_t *output_data_start,				
				  size_t output_data_max_size,
				  size_t *actual_output_data_size);

#endif

#endif
