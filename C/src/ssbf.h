#ifndef SSBF_H
#define SSBF_H

#include <inttypes.h>

#define SSBFv1_MAGIC_NUMBER 0x19345601
#define SSBFv1_VERSION 1

enum ssbf_errors {
        SSBF_NO_ERROR = 0,
        SSBF_GENERIC_ERROR = 1,
        SSBF_NOT_ENOUGHT_DATA = 1,
        SSBF_CHECKSUM_FAILED = 2,
        SSBF_COMPRESSION_FAILED = 3,
        SSBF_DECRYPTION_FAILED = 4,
};

enum SSBF_MAIN_HEADER_FLAGS {
        SSBF_MAIN_HEADE_FLAG_USE_META_EXTENSION = 1,
        SSBF_MAIN_HEADE_FLAG_USE_ENCRYPTION_EXTENSION = 2,
};

enum SSBF_CRYPTO_FLAGS {
        SSBF_ENCRYPTION_HEADER_FLAG_USE_POLY1305 = (1 << 0),
        SSBF_ENCRYPTION_HEADER_FLAG_USE_CHACHA20 = (1 << 3),
};

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
		      size_t *actual_output_data_size);


enum ssbf_errors ssbf_explain( uint8_t *input_data_start,
			       size_t input_data_size);

#endif
