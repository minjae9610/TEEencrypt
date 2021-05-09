/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

void caesar_prepare_op(TEEC_Operation *op, char *in, size_t in_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op->params[1].tmpref.buffer = in;
	op->params[1].tmpref.size = in_sz;
}

void rsa_prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_sz;
}

void caesar_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	char caesar_ciphertext[MAX_PLAIN_LEN_1024] = {0,};
	int encryptedKey = 0;
	caesar_prepare_op(&op, in, in_sz);

	printf("Plaintext : %s", in);

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_ENC_TEXT_Caesar, &op,
			 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, origin);

	memcpy(caesar_ciphertext, op.params[1].tmpref.buffer, in_sz);
	encryptedKey = op.params[0].value.a;
	printf("Ciphertext : %s", caesar_ciphertext);
	printf("Cipherkey :  %d\n", encryptedKey);

	char *writeFilePath = malloc(sizeof(char) * (17 + strlen(out)));
	strcpy(writeFilePath, "/root/enc_caesar_");
	strcat(writeFilePath, out);
	FILE *wfp = fopen(writeFilePath, "wt");
	free(writeFilePath);
	if (wfp != NULL){
		fprintf(wfp, "%d\n%s", encryptedKey, caesar_ciphertext);
		fclose(wfp);
	}
}

void caesar_decrypt(struct ta_attrs *ta, char *in, size_t in_sz, int encryptedKey, char *out)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	char plaintext[MAX_PLAIN_LEN_1024] = {0,};
	caesar_prepare_op(&op, in, in_sz);

	op.params[0].value.a = encryptedKey;
	printf("Ciphertext : %s", in);
	printf("Cipherkey :  %d\n", encryptedKey);

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_DEC_TEXT_Caesar, &op,
			 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
		res, origin);

	memcpy(plaintext, op.params[1].tmpref.buffer, in_sz);
	printf("Plaintext : %s", plaintext);

	char *writeFilePath = malloc(sizeof(char) * (17 + strlen(out)));
	strcpy(writeFilePath, "/root/dec_caesar_");
	strcat(writeFilePath, out);
	FILE *wfp = fopen(writeFilePath, "wt");
	free(writeFilePath);
	if (wfp != NULL){
		fputs(plaintext, wfp);
		fclose(wfp);
	}
}

void rsa_gen_keys(struct ta_attrs *ta) {
	TEEC_Result res;

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_GENKEYS_RSA, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_GENKEYS_RSA) failed %#x\n", res);
	printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	printf("\n============ RSA ENCRYPT CA SIDE ============\n");
	rsa_prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_ENC_TEXT_RSA,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_ENC_TEXT_RSA) failed 0x%x origin 0x%x\n",
			res, origin);
	printf("\nThe text sent was encrypted: %s\n", out);
}

void rsa_decrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	printf("\n============ RSA DECRYPT CA SIDE ============\n");
	rsa_prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_TEEencrypt_CMD_DEC_TEXT_RSA, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_DEC_TEXT_RSA) failed 0x%x origin 0x%x\n",
			res, origin);
	printf("\nThe text sent was decrypted: %s\n", (char *)op.params[1].tmpref.buffer);
}

int main(int argc, char *argv[])
{
	if (argc != 4){
		printf("Wrong options\n");
	}else{
		char *readFilePath = malloc(sizeof(char) * (6 + strlen(argv[2])));
		strcpy(readFilePath, "/root/");
		strcat(readFilePath, argv[2]);
		FILE *rfp = fopen(readFilePath, "rt");
		free(readFilePath);
		if (rfp == NULL){
			printf("Can't open file\n");
		}else{
			struct ta_attrs ta;
			char input_text[MAX_PLAIN_LEN_1024] = {0,};
			char rsa_ciphertext[RSA_CIPHER_LEN_1024] = {0,};
			int encryptedKey = 0;

			prepare_ta_session(&ta);

			if (!strcmp(argv[1], "-e")){
				fread(input_text, 1, MAX_PLAIN_LEN_1024, rfp);
				if (!strcmp(argv[3], "Caesar")){
					printf("========================Encryption========================\n");
					caesar_encrypt(&ta, input_text, MAX_PLAIN_LEN_1024, argv[2]);
				}else if (!strcmp(argv[3], "RSA")){
					rsa_gen_keys(&ta);
					rsa_encrypt(&ta, input_text, MAX_PLAIN_LEN_1024, rsa_ciphertext, RSA_CIPHER_LEN_1024);

					char *writeFilePath = malloc(sizeof(char) * (14 + strlen(argv[2])));
					strcpy(writeFilePath, "/root/enc_rsa_");
					strcat(writeFilePath, argv[2]);
					FILE *wfp = fopen(writeFilePath, "wt");
					free(writeFilePath);
					if (wfp != NULL){
						fwrite(rsa_ciphertext, RSA_CIPHER_LEN_1024, 1, wfp);
						fclose(wfp);
					}
				}
			}else if (!strcmp(argv[1], "-d")){
				if (!strcmp(argv[3], "Caesar")){
					printf("========================Decryption========================\n");
					fscanf(rfp, "%d", &encryptedKey);
					fgetc(rfp);
					fread(input_text, 1, MAX_PLAIN_LEN_1024, rfp);
					caesar_decrypt(&ta, input_text, MAX_PLAIN_LEN_1024, encryptedKey, argv[2]);
				}
			}
			fclose(rfp);
			terminate_tee_session(&ta);
		}
	}
	return 0;
}
