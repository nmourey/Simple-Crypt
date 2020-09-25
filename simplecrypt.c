/* 
 * Programmer : Nathan A. Mourey II
 * Program    : SimpleCrypt
 * Date       : October 21st 2020
 * Program    : Simple Crypt -- Inspired by CompTIA Security+ book.
 * Copyright  : Nathan A. Mourey II
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simplecrypt.h"

int main(int argc, char *argv[]) {
	CryptFile *cf = malloc(sizeof(CryptFile));
	int chunk_size;
	int remove_input_file;
	int remainder_size;
	int passes;
	int num_passes = 0;
	int opt;
	char *file_in, *file_out;


	/* get commadline options. */
	while ((opt = getopt(argc, argv, "vhrp:i:o:")) != -1){
		switch(opt){
			case 'p':
				if (!(passes = atoi(optarg))){
					printf("Usage : %s -h -v [-p passes] [-i filein] [-o fileout]\n", argv[0]);
					printf("passes must be an integer.\n");
					exit(1);
				}			
				break;
			case 'r':
				remove_input_file = 1;
				break;
			case 'i':
				file_in = optarg;
				break;
			case 'o':
				file_out = optarg;
				break;
			case 'h':
				printf("Usage : %s -h -v [-r remove] [-p passes] [-i filein] [-o fileout]\n", argv[0]);
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
		printf("Usage : %s -h -v [-r remove] [-p passes] [-i filein] [-o fileout]\n", argv[0]);
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
			// is unlink needed?
			unlink(file_out);
			free(cf);
			exit(1);

		}

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

	/* done with input file. unlink if requested */
	if (remove_input_file){
		unlink(file_in);
	}

	/* free memory & flush buffers */
	munmap(cf->data_out_buffer, cf->stat_buff.st_size);
	free(cf);
	exit(0);
}
