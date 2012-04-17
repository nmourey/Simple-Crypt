/* 
 * Programmer : Nathan A. Mourey II
 * Program    : SimpleCrypt
 * Date       : October 21st 2011
 * Program    : Simple Crypt -- Inspired by CompTIA Security+ book.
 * Copyright  : GLPv3
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simplecrypt.h"

int main(int argc, char *argv[])
{
	int chunk_size;
	int remainder_size;
	int passes;
	int num_passes = 0;
	int opt;
	char pass_str[32];
	CryptFile *cf = malloc(sizeof(CryptFile));
	
	char *file_in, *file_out;

	/* get commadline options. */
	while ((opt = getopt(argc, argv, "vhp:i:o:")) != -1){
		switch(opt){
			case 'p':
				if (!(passes = atoi(optarg))){
					printf("Usage : %s -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
					printf("passes must be an integer.\n");
					exit(1);
				}			
				break;
			case 'i':
				file_in = optarg;
				break;
			case 'o':
				file_out = optarg;
				break;
			case 'h':
				printf("Usage : %s -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
				exit(1);
				break;
			case 'v':
				printf("%s\n", COPY);
				exit(1);
			default:
				exit(1);
		}
	}

	if(!(passes && file_in && file_out) || (argc <= 1)){
		printf("Usage : %s -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
		exit(1);
	}

	/* read file to encrypt/decrypt into memory. */
	read_file(cf, file_in);	

	/* do encryption passes. */
	do {
		/* check if password is acceptable. */
		if (get_pass() == -1){

			/* free memory and exit */
			if (cf->data_in_buffer)
				free(cf->data_in_buffer);

			if (cf->data_out_buffer)
				free(cf->data_in_buffer);

			free(cf);
			exit(1);

		}

		/* pass_phrase is global and is defined in the header. */
		cf->pass_len = (strlen(pass_phrase)-1);
		pass_phrase[cf->pass_len] = '\0';
	
		cf->pass = pass_phrase;
		cf->chunk_size = (cf->file_length / cf->pass_len);
		cf->remaining = (cf->file_length % cf->pass_len);

		/* encryt data */
		encrypt_data(cf);

		/* FIXME: Free memory here here before assignment? */
		cf->data_in_buffer = cf->data_out_buffer;

		num_passes++;
	} while (num_passes < passes);

	write_file(cf, file_out);

	/* free memory. */
	free(cf->data_in_buffer);
	free(cf);

	exit(0);
}
