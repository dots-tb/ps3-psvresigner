//ps3-psvresigner by @dots_tb - Resigns non-console specific PS3 PSV savefiles. PSV files embed PS1 and PS2 save data. This does not inject!
//With help from the CBPS (https://discord.gg/2nDCbxJ) , especially:
// @AnalogMan151
// @teakhanirons
// Silica
// @notzecoxao
// @nyaaasen 

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#include "aes.h"
#include "sha1.h"

#define SEED_OFFSET 0x8
#define HASH_OFFSET 0x1c
#define TYPE_OFFSET 0x3C

#define PSV_MAGIC 0x50535600

uint8_t key[2][0x10] = {
							{0xFA, 0x72, 0xCE, 0xEF, 0x59, 0xB4, 0xD2, 0x98, 0x9F, 0x11, 0x19, 0x13, 0x28, 0x7F, 0x51, 0xC7}, 
							{0xAB, 0x5A, 0xBC, 0x9F, 0xC1, 0xF4, 0x9D, 0xE6, 0xA0, 0x51, 0xDB, 0xAE, 0xFA, 0x51, 0x88, 0x59}
						};
uint8_t iv[0x10] = {0xB3, 0x0F, 0xFE, 0xED, 0xB7, 0xDC, 0x5E, 0xB7, 0x13, 0x3D, 0xA6, 0x0D, 0x1B, 0x6B, 0x2C, 0xDC};



void XorWithByte(uint8_t* buf, uint8_t byte, int length)
{
	for (int i = 0; i < length; ++i) {
    	buf[i] ^= byte;
	}
}

static void usage(char *argv[])
{	
	printf("Usage: %s <savefile>.PSV\n",argv[0]);
}

void generateHash(const char *input, char *dest, size_t sz, int type) {
	struct AES_ctx aes_ctx;

	uint8_t salt[0x40];
	uint8_t work_buf[0x14];
		
	uint8_t *salt_seed = input + SEED_OFFSET;
	memset(salt , 0, sizeof(salt));
	
	printf("Type detected: %x\n", type);
	if(type == 1) {//PS1
		//idk why the normal cbc doesn't work.
		AES_init_ctx_iv(&aes_ctx, key[1], iv);
		memcpy(work_buf, salt_seed, 0x10);
		AES_ECB_decrypt(&aes_ctx, work_buf);
		memcpy(salt, work_buf, 0x10);

		memcpy(work_buf, salt_seed, 0x10);
		AES_ECB_encrypt(&aes_ctx, work_buf);
		memcpy(salt + 0x10, work_buf, 0x10);

		XorWithIv(salt, iv);
			
		memset(work_buf, 0xFF, sizeof(work_buf));
		memcpy(work_buf, salt_seed + 0x10, 0x4);
		XorWithIv(salt + 0x10, work_buf);
		
	} else if(type == 2) {//PS2
		uint64_t laid_paid[2]  = {	
								__builtin_bswap64((uint64_t)0x1070000002000001L),
								__builtin_bswap64((uint64_t)0x10700003FF000001L)
								};
		memcpy(salt, salt_seed, 0x14);
		XorWithIv(key[0], laid_paid);
		AES_init_ctx_iv(&aes_ctx, key[0], iv);
		AES_CBC_decrypt_buffer(&aes_ctx, salt, 0x40);
	}
	
	
	memset(salt + 0x14, 0, sizeof(salt) - 0x14);
	
	
	XorWithByte(salt, 0x36, 0x40);
		
	SHA1_CTX sha1_ctx_1;	
	SHA1Init(&sha1_ctx_1);
	
	SHA1Update(&sha1_ctx_1, salt, 0x40);

	memset(input + HASH_OFFSET, 0, 0x14);
	SHA1Update(&sha1_ctx_1, input, sz);
				
	XorWithByte(salt, 0x6A, 0x40);

	SHA1Final(work_buf, &sha1_ctx_1);

	SHA1_CTX sha1_ctx_2;
	SHA1Init(&sha1_ctx_2);
	SHA1Update(&sha1_ctx_2, salt, 0x40);
	SHA1Update(&sha1_ctx_2, work_buf, 0x14);

	SHA1Final(dest, &sha1_ctx_2);
}

int main(int argc, char **argv)
{
	printf("\n=====ps3-psvresigner by @dots_tb=====");
	printf("\nWith CBPS help especially: @AnalogMan151, @teakhanirons, Silica, @nyaaasen, and @notzecoxao\n");
	printf("Resigns non-console specific PS3 PSV savefiles. PSV files embed PS1 and PS2 save data. This does not inject!\n\n");
	if (argc != 2) {
		usage(argv);
		return 1;
	}

	FILE *fin = 0, *fout = 0;
	fin = fopen(argv[1], "rb");
	if (!fin) {
		perror("Failed to open input file");
		goto error;
	}

	fseek(fin, 0, SEEK_END);
	size_t sz = ftell(fin);
	printf("File SZ: %x\n", sz);
	fseek(fin, 0, SEEK_SET);
	
	uint8_t *input = (unsigned char*) calloc (1, sz);
	uint32_t *input_ptr = (uint32_t*) input;
	fread(input, sz,1,fin);
	
	if(input_ptr[0] != PSV_MAGIC) {
		perror("Not a PSV file");
		free(input);
		goto error;
	}
	
	printf("Old signature: ");
	for(int i = 0; i < 0x14; i++ ) {
		printf("%02X ",  input[HASH_OFFSET + i]);
	}
	printf("\n");
	generateHash(input, input + HASH_OFFSET, sz, *(input + TYPE_OFFSET));
	
		
	printf("New signature: ");
	for(int i = 0; i < 0x14; i++ ) {
		printf("%02X ", input[HASH_OFFSET + i]);
	}
	printf("\n");
		
	char output_path[128];
	sprintf(output_path,"%s.new.PSV",argv[1]);
	fout = fopen(output_path, "wb");
	if (!fout) {
		perror("Failed to open output file");
		free(input);
		goto error;
	}
	fwrite(input,  1, sz, fout);
	free(input);
	printf("PSV resigned successfully: %s\n", output_path);


error:
	if (fin)
		fclose(fin);
	if (fout)
		fclose(fout);	

	return 0;
}
