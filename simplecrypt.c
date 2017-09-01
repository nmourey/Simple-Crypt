/* 
 * Programmer : Nathan A. Mourey II
 * Program    : SimpleCrypt
 * Date       : October 21st 2011-2016
 * Program    : Simple Crypt -- Inspired by CompTIA Security+ book.
 * Copyright  : GLPv3
 * Notice:    : set tabstop = 2
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
	int delete = 0;
	int num_passes = 0;
	int opt;
	char pass_str[32];
	CryptFile *cf = malloc(sizeof(CryptFile));

	char *file_in, *file_out;

	/* get commadline options. */
	while ((opt = getopt(argc, argv, "vhdp:i:o:")) != -1){
		switch(opt){
			case 'p':
				if (!(passes = atoi(optarg))){
					printf("Usage : %s -d -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
					printf("passes must be an integer.\n");
					exit(1);
				}
				break;
			case 'd':
				delete = 1;
				break;
			case 'i':
				file_in = optarg;
				break;
			case 'o':
				file_out = optarg;
				break;
			case 'h':
				printf("Usage : %s -d -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
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
		printf("Usage : %s -d -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
		exit(1);
	}

	/* open files for mem mapped I/O */
	map_files(cf, file_in, file_out);

	/* do encryption passes. */
	do {
		/* check if password is acceptable. */
		if (get_pass() == -1){

			/* free buffer */
			if (cf->data_out_buffer)
				munmap(cf->data_out_buffer, cf->stat_buff.st_size);

			/* delete output file. */
			unlink(file_out);
			free(cf);
			exit(1);

		} /* end if */

		/* pass_phrase is global and is defined in the header. */
		cf->pass_len = (strlen(pass_phrase)-1);
		pass_phrase[cf->pass_len] = '\0';

		cf->pass = pass_phrase;
		cf->chunk_size = (cf->file_length / cf->pass_len);
		cf->remaining = (cf->file_length % cf->pass_len);

		/* encrypt data */
		encrypt_data(cf);

		num_passes++;
	} while (num_passes < passes);

	/* free memory. */
	munmap(cf->data_out_buffer, cf->stat_buff.st_size);
	free(cf);

	exit(0);
}
