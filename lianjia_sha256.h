//
// Created by wanna on 2021/12/27.
//

#ifndef LIANJIA_LIANJIA_SHA256_H
#define LIANJIA_LIANJIA_SHA256_H




typedef unsigned int uint_32;
uint_32 bswap32(uint_32 x);
void sha256_init(unsigned int *);
void sha256_block_data_order(unsigned int *, unsigned int *, int );
void sha256_update(unsigned int *,unsigned char *, unsigned int  );
void sub_E0AC(unsigned char *outbuf,unsigned char *input_data, unsigned int input_len);
void sha256_final(unsigned int *a1,unsigned int *a2);
void sub_E1AC(unsigned int *a1,unsigned char *a2, size_t a3);
void gen_sign(unsigned char* data_input,unsigned char *md5_input,unsigned char *output);
void gen_salt(unsigned char *out);
void printbuf(unsigned int *num,int size);
#endif //LIANJIA_LIANJIA_SHA256_H
