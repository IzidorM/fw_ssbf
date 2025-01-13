#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

//#include "debug_io.h"

#include "lz4.h"
#include "lz4hc.h"

#include "monocypher.h"

#include "ssbf.h"
#include "ssbf_internal.h"

uint8_t bsd_checksum8_from(uint8_t start_checksum, uint8_t *data, size_t data_size)
{
        uint8_t checksum = start_checksum;
        uint32_t i;
        for (i = 0; data_size > i; i++)
        {
                checksum = (uint8_t) ((checksum >> 1) + ((checksum & 0x1) << 7));
                checksum = checksum + data[i];
        }
        return checksum;
}

uint8_t bsd_checksum8(uint8_t *data, size_t data_size)
{
        return bsd_checksum8_from(0, data, data_size);
}

uint16_t bsd_checksum16(uint8_t *data, size_t data_size)
{
        uint16_t checksum = 0;
        uint32_t i;
        for (i = 0; data_size > i; i++)
        {
                checksum = (uint16_t) ((checksum >> 1) + ((checksum & 1) << 15));
                checksum += data[i];
        }
        return checksum;
}

uint32_t ssbf_compress_lz4(uint8_t *data_in, uint8_t *data_out, 
			  uint32_t data_size_to_compress, 
			  uint8_t *flags)
{

	uint32_t r = LZ4_compress_HC ((char *) data_in, (char *) data_out,
				 (int) data_size_to_compress, 
				 (int) data_size_to_compress, 
				 LZ4HC_CLEVEL_MAX);

        //int r = LZ4_compress_default((char *) data_in,
        //                             (char *) data_out,
        //                             data_size_to_compress, max_block_size);


        // compression failed or bigger than original
        if (0 == r || data_size_to_compress <= r) 
        {
                // just copy original data
                memcpy(data_out, data_in, data_size_to_compress);
                r = data_size_to_compress;
        }
	else
	{
		*flags |= BHF_BLOCK_COMPRESSED;
	}
        
        return r;
}

int32_t sdf_decompress_lz4(uint8_t *data_in, uint8_t *data_out, 
			    size_t compressed_data_size, size_t max_block_size)
{
        int32_t r = LZ4_decompress_safe((char *) data_in,
                                        (char *) data_out,
                                        compressed_data_size, max_block_size);
        return r;
}


void ssbf_crypto_inplace_chacha20(uint8_t key [ 32],
				  uint8_t nonce [ 24],
				  uint8_t *data,
				  uint32_t data_size,
				  uint8_t *flags)
{
	crypto_chacha20_x(data, data, data_size, key, nonce, 0);

	//crypto_wipe(key,        32);

	*flags |= BHF_BLOCK_ENCRYPTED;
}



