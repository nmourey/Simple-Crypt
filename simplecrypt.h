/* 
 * Programmer : Nathan A. Mourey II
 * Program    : SimpleCrypt
 * Date       : October 21st 2011
 * Program    : Simple Crypt -- Inspired by CompTIA Security+ book.
 * Copyright  : GLPv3
 * Referance  : http://www.linuxquestions.org/questions/programming-9/c-howto-read-binary-file-into-buffer-172985/
 * 	      : for fseek and ftell functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* for preprocessor. */
#define MIN_PASS_LENGTH 10
#define MAX_PASS_LENGTH 128

#define INPUT_BUFFER 132

#define COPY "Simple Crypt v1.3 : Copyright (C) 2011, 2012 Nathan A. Mourey II <nmoureyii@ne.rr.com>"

/* global variable */
char pass_phrase[INPUT_BUFFER];

/* data stucture for CryptFile infomation. */
typedef struct CryptFile {
        char *data_in_buffer;
        char *data_out_buffer;
	char *pass;
	int pass_len;
	int chunk_size;
	int remaining;
	/* (data in size) length of data_in_buffer */
        int file_length;	
} CryptFile;

/* get users pass phrase. */
int get_pass(void)
{
	printf("Enter encryption key [between %i and %i charaters] : ", MIN_PASS_LENGTH, MAX_PASS_LENGTH);
	fgets(pass_phrase, sizeof(pass_phrase), stdin);

	if ( ((strlen(pass_phrase)-1) <= MIN_PASS_LENGTH) || ((strlen(pass_phrase)-1) >= MAX_PASS_LENGTH) ){
		fprintf(stderr, "Error : Encryption key must be longer that %i charaters and %i charaters or less.\n", 
		MIN_PASS_LENGTH, MAX_PASS_LENGTH);
		fprintf(stderr, "Error : No file written.\n");
		printf("%s\n", COPY);
		return -1;
	}
}

/* read a file into a buffer. */
void read_file(CryptFile *cf, char *file_name)
{
	FILE *file;

	file = fopen(file_name, "rb");
	
	if (!file) {
		fprintf(stderr, "Error could not open file : %s\n", file_name);
		exit(1);
	}

	/* go to end of file. */
	fseek(file, 0, SEEK_END);
	/* get lenght of file. */
	cf->file_length =  ftell(file);
	/* go back to begining of file. */
	fseek(file, 0, SEEK_SET);

	/* Allocate buffers */
	/* check that memory was allocaed. */
	if ( !(cf->data_in_buffer = malloc(cf->file_length+1)) ) {
		fprintf(stderr, "Error could not allocate memory.\n");
		fclose(file);
		exit(1);
	}

	/* check that memory was allocaed. */
	if ( !(cf->data_out_buffer = malloc(cf->file_length+1)) ) {
		fprintf(stderr, "Error could not allocate memory.\n");
		fclose(file);
		exit(1);
	}

	/* read data into buffer. */
	fread(cf->data_in_buffer, cf->file_length, 1, file);
	fclose(file);
}

/* write a buffer out into a file.  */
void write_file(CryptFile *cf, char *file_name)
{
	FILE *file;
	if (file = fopen(file_name, "wb")){
		fwrite(cf->data_out_buffer, cf->file_length, 1, file);
		/* free(cf->data_out_buffer); */
	} else {
		fprintf(stderr, "Could not open file %s for writing.", file_name);
		exit(1);
	}
	fclose(file);
}

/* XOR encryption algo. */
void encrypt_data(CryptFile *cf)
{
	int i, j, k = 0;

	/* process each chunk. */
	for (i = 0; i < cf->chunk_size; i++){
		for(j = 0; j < cf->pass_len; j++){	
			cf->data_out_buffer[k] = cf->data_in_buffer[k] ^ cf->pass[j];
			k++;
		}
	}

	/* process the remaining data. */
	for (i = 0; i < cf->remaining; i++){
		cf->data_out_buffer[k] = cf->data_in_buffer[k] ^ cf->pass[i];
		k++;
	}
}
