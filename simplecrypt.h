/* 
 * Programmer : Nathan A. Mourey II
 * Program    : SimpleCrypt
 * Date       : October 21st 2020
 * Program    : Simple Crypt -- Inspired by CompTIA Security+ book.
 * Copyright  : Nathan A. Mourey II
 * Referance  : http://www.linuxquestions.org/questions/programming-9/c-howto-read-binary-file-into-buffer-172985/
 * 	      : for fseek and ftell functions.
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* for preprocessor. */
#define MIN_PASS_LENGTH 5

/* 1024 bits */
#define MAX_PASS_LENGTH 128

#define INPUT_BUFFER 128

#define COPY "Simple Crypt v2.1.0 : Copyright (C) 2011-2020 Nathan A. Mourey II"

/* global variable */
char pass_phrase[INPUT_BUFFER];

/* data stucture for CryptFile infomation. */
typedef struct CryptFile {
	int in_file, out_file;
        char *data_in_buffer;
        char *data_out_buffer;
	char *pass;
	int pass_len;
	int chunk_size;
	int remaining;
	/* (data in size) length of data_in_buffer */
        int file_length;	
	struct stat stat_buff;
} CryptFile;

/* get users pass phrase. */
int get_pass(void)
{
	/* possible goto here? */
	sc_repass:
	printf("Enter encryption key [between %i and %i charaters] : ", MIN_PASS_LENGTH, MAX_PASS_LENGTH);
	fgets(pass_phrase, sizeof(pass_phrase), stdin);

	if ( ((strlen(pass_phrase)-1) <= MIN_PASS_LENGTH) || ((strlen(pass_phrase)-1) >= MAX_PASS_LENGTH) ){
		fprintf(stderr, "Error : Encryption key must be longer than %i charaters and %i charaters or less.\n", 
		MIN_PASS_LENGTH, MAX_PASS_LENGTH);
		goto sc_repass;
	}
}

/* map input and output files */
void map_files(CryptFile *cf, char *file_in, char *file_out)
{

	/* open input file. */
	if ( (cf->in_file = open(file_in, O_RDONLY)) < 0) {
		fprintf(stderr, "Error could not open file : %s\n", file_in);
		exit(1);
	}

	/* fill stat_buff with file info. */
	fstat(cf->in_file, &cf->stat_buff);

	/* open output file. */
	if  ( (cf->out_file = open(file_out, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0644)) < 0 ){
		fprintf(stderr, "Error could not open file : %s\n", file_out);
		exit(1);
	}

	/* verify that the output file is writeable. */
	lseek(cf->out_file, cf->stat_buff.st_size-1, SEEK_SET);
	if (write(cf->out_file, "", 1) != 1)
		fprintf(stderr, "Unable to write\n");
	
	cf->file_length = cf->stat_buff.st_size;
	
	/* memory mapped I/O */
	cf->data_in_buffer = mmap(0, cf->stat_buff.st_size, PROT_READ, MAP_SHARED, cf->in_file, 0);
	cf->data_out_buffer = mmap(0, cf->stat_buff.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, cf->out_file, 0);

	/* create working buffer */
	memcpy(cf->data_out_buffer, cf->data_in_buffer, cf->stat_buff.st_size);

	/* unmap input buffer */
	munmap(cf->data_in_buffer, cf->stat_buff.st_size);
	
	/* close file handles */
	/* remove and close in main() */
	close(cf->in_file);
	close(cf->out_file);
}

/* XOR encryption algo. */
void encrypt_data(CryptFile *cf)
{
	int i, j, k = 0;

	/* process each chunk. */
	for (i = 0; i < cf->chunk_size; i++){
		for(j = 0; j < cf->pass_len; j++){	
			cf->data_out_buffer[k] = cf->data_out_buffer[k] ^ cf->pass[j];
			k++;
		}
	}

	/* process the remaining data. */
	for (i = 0; i < cf->remaining; i++){
		cf->data_out_buffer[k] = cf->data_out_buffer[k] ^ cf->pass[i];
		k++;
	}
}
