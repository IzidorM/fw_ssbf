#ifndef SSBF_COMMON_H
#define SSBF_COMMON_H

#include <inttypes.h>

uint8_t bsd_checksum8(uint8_t *data, size_t data_size);
uint16_t bsd_checksum16(uint8_t *data, size_t data_size);

uint32_t ssbf_compress_lz4(uint8_t *data_in, uint8_t *data_out, 
			   int32_t data_size_to_compress, 
			   uint8_t *flags);

int32_t sdf_decompress_lz4(uint8_t *data_in, uint8_t *data_out, 
			   size_t compressed_data_size, 
			   size_t max_block_size);

void ssbf_crypto_inplace_chacha20(uint8_t key [ 32],
				  uint8_t nonce [ 24],
				  uint8_t *data,
				  uint32_t data_size,
				  uint8_t *flags);

#endif
