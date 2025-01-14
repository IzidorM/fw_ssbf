#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <time.h>
#include <sys/time.h>

#include "ssbf.h"
#include "ssbf_internal.h"

#define KEY_SIZE 32
#define NONCE_SIZE 24

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
	(void) argc;
	(void) argv;
//        if (argc != 2)
//        {
//                printf("Wrong args\n");
//                return 1;
//        }
//
//        char *data_filename = argv[1];
        char *data_filename = "tmp.ssbf";
	printf("Opening file: %s\n", data_filename);

	size_t input_file_buffer_size = 0;
	uint8_t *input_file_buffer_start = NULL;

	if (read_file_in_a_buffer(data_filename, 
				  &input_file_buffer_start,
				  &input_file_buffer_size))
	{
		return 1;
	}

	enum ssbf_errors r = ssbf_explain(
		input_file_buffer_start, input_file_buffer_size);

	if (r)
	{
		printf("ssbf explain failed\n");
		return 1;
	}

	return 0;
}

