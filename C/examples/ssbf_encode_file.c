#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <time.h>
#include <sys/time.h>

#include "ssbf.h"

#define KEY_SIZE 32
#define NONCE_SIZE 24

// caller needs to assure that time_array is 8 or more bytes long
void get_current_time(uint8_t *time_array)
{

    struct timeval tv;
    struct tm* ptm;

    gettimeofday(&tv, NULL);
    ptm = localtime(&tv.tv_sec);

    time_array[0] = ptm->tm_year - 100; // Year since 1900
    time_array[1] = ptm->tm_mon + 1;     // Month (0-11)
    time_array[2] = ptm->tm_mday;        // Day of the month
    time_array[3] = ptm->tm_hour;        // Hour of the day
    time_array[4] = ptm->tm_min;         // Minute
    time_array[5] = ptm->tm_sec;         // Second

    // Calculate subseconds in milliseconds
    long subseconds = tv.tv_usec / 1000;
    // Encode subseconds in two bytes
    time_array[6] = (subseconds >> 8) & 0xFF;
    time_array[7] = subseconds & 0xFF;

//    printf("Time array: ");
//    for (int i = 0; i < 8; i++) {
//        printf("%i ", time_array[i]);
//    }
//    printf("\n");
}

static int read_file_in_a_buffer(char *file_name, 
				 uint8_t **buffer, size_t *buff_size)
{
	FILE * fp;
        fp = fopen (file_name,"rb");
        if (NULL == fp)
        {
                printf("File not found\n");
                return 1;
        }

        fseek(fp, 0L, SEEK_END);
        *buff_size = ftell(fp);
        printf("There are %zu bytes in an input file\n", *buff_size);

        *buffer = malloc(*buff_size);
	if (NULL == *buffer)
	{
		return 1;
	}
	

        rewind(fp);
        fread(*buffer, 1, *buff_size, fp);
	fclose(fp);
	return 0;
}


int main(int argc, char **argv)
{
        char *data_filename = NULL;
	char *output_filename = NULL;
        char *key_filename = NULL;
//        char *meta_data_filename = NULL;
	
        uint32_t block_size = 1024;
        int c;
        while ((c = getopt(argc, argv, "k:f:b:m:o:h")) != -1)
        {
        	switch (c)
        	{
        	case 'f':
                        
        		data_filename = optarg;
        		break;

        	case 'k':
        		key_filename = optarg;
        		break;
        	case 'b':
        		block_size = atoi(optarg);
                        printf("using block size: %i\n", block_size);
        		break;

//        	case 'm':
//        		meta_data_file = optarg;
//        		break;

        	case 'o':
        		output_filename = optarg;
        		break;

        	case 'h':
        		printf("Usage flags:\n");
        		printf("-f <filename> - input file to encode to ssbf\n");
                        printf("-b <block_size - size of the block\n");
        		printf("-k <key_filename> - filename where encryption key is stored\n");
        		printf("-o <filename> - output file name\n");

        		return 1;

        	case '?':
    			return 1;
        	default:
        		abort();
        	}
        }

        if ((NULL == data_filename) || (NULL == key_filename))
        {
                printf("Missing data file name or encryption key file");
                return 1;
        }

        size_t input_file_buffer_size = 0;
        uint8_t *input_file_buffer_start = NULL;

	int r = read_file_in_a_buffer(data_filename,
				      &input_file_buffer_start,
				      &input_file_buffer_size);

        if (r)
        {
                printf("File not found\n");
                return 1;
        }

        uint8_t *main_key = NULL; //[32];
	size_t main_key_size = 0;
	r = read_file_in_a_buffer(key_filename,
				  &main_key,
				  &main_key_size);

        if (r)
        {
                printf("Error reading key from file\n");
                return 1;
        }

	if (32 != main_key_size)
	{
		if (33 == main_key_size && (10 == main_key[main_key_size-1]))
		{
			// remove the newline from the end of the key
			printf("removing new line from the main key\n");
			main_key[main_key_size] = 0;
			main_key_size -= 1;
		}
		else
		{
			printf("E: wrong main key size  %i (%i)\n", 
			       (int) main_key_size, main_key[main_key_size-1]);
			return 1;
		}
	}

	// nonce must be unique for every build, because if we reuse it
	// with the same key, the key could be exposed
	// to get unique nonce everytime we use current date + random numbers
	// first 8 bytes are date (yy(from 2000)-mm-dd-hh-min-sec-msec)
	uint8_t nonce[NONCE_SIZE];
	get_current_time(nonce);


	unsigned char data_key[32];
	FILE *fp = fopen ("/dev/urandom", "rb");
	if (NULL == fp) {
		return 1;
	}

	int data_key_size = fread(data_key, 1, sizeof(data_key), fp);

	// fill the rest of the nonce (8-23 bytes with random numbers)
	fread(&nonce[8], 1, NONCE_SIZE-8, fp);

	fclose(fp);

	if (data_key_size != sizeof(data_key)) {
		printf("E: wrong data key size  %i\n", 
		       (int) data_key_size);		
		return 1;
	}
    
	// print the random data key
	printf("data key: ");
	for (int i = 0; i < 32; i++) {
		printf("%02x", data_key[i]);
	}
	printf("\n");

	printf("nonce: ");
	for (int i = 0; i < 24; i++) {
		printf("%02x", nonce[i]);
	}
	printf("\n");

	// THIS needs to be uniqu for every encoded file
	// because if it is used twice, the main key could be exposed

	uint8_t *output_data_start = malloc(2*input_file_buffer_size + 1);
	size_t encoded_file_size = 0;

	// TODO: Implement getting meta data and meta id from file
	uint8_t meta_payload_data[4] = {1,2,3,4};

	ssbf_encode_data(main_key, //[32],
			 nonce, //[24]
			 data_key, //[32]
			 0x1234,
			 meta_payload_data,
			 sizeof(meta_payload_data),
			 block_size,
			 (uint8_t *)input_file_buffer_start,
			 input_file_buffer_size,
			 output_data_start,
			 sizeof(output_data_start),
			 &encoded_file_size);

	printf("%zu -> %zu\n", input_file_buffer_size, encoded_file_size);

        printf("ssbf encoded file size: %zu\n", encoded_file_size);

        printf("compression ratio: %f\n", 
	       (double) encoded_file_size / input_file_buffer_size);

	uint32_t input_filename_len = strlen(data_filename);
	char output_file_name[input_filename_len+1+5];

	if (NULL == output_filename)
	{


		memcpy(output_file_name, data_filename, input_filename_len);

		output_file_name[input_filename_len] =   '.';
		output_file_name[input_filename_len+1] = 's';
		output_file_name[input_filename_len+2] = 's';
		output_file_name[input_filename_len+3] = 'b';
		output_file_name[input_filename_len+4] = 'f';
		output_file_name[input_filename_len+5] = '\0';

		output_filename = output_file_name;
	}


	FILE * fpo;
        fpo = fopen ((char *) output_filename, "w");
        if (NULL == fpo)
        {
                printf("File not found %s\n", (char *) output_file_name);
                return 1;
        }
        
        printf("Writing to %s %zu bytes\n", 
	       output_filename, encoded_file_size);
        fwrite(output_data_start, 1, encoded_file_size, fpo);

        fclose(fpo);
        printf("Done\n");
}

