//
// Created by wanna on 2021/12/27.
//

#include <cstdio>
#include <cstring>
#include "lianjia_sha256.h"
#include "md5.h"

unsigned int sha256_const_value_8[] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
unsigned int sha256_const_table_64[] = {0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B,
                                         0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01,
                                         0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7,
                                         0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC,
                                         0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152,
                                         0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
                                         0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC,
                                         0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                                         0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819,
                                         0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08,
                                         0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F,
                                         0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
                                         0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2  };


uint_32 bswap32(uint_32 x)
{
    return (((uint_32)(x) & 0xff000000) >> 24) | \
           (((uint_32)(x) & 0x00ff0000) >> 8) | \
           (((uint_32)(x) & 0x0000ff00) << 8) | \
           (((uint_32)(x) & 0x000000ff) << 24) ;
}

template<class T> T ROR4_(T value, uint count)
{
    return (value << (0x20 - count)) | (value >> count);
}


void sha256_init(unsigned int *result)
{
    for (int i = 0; i != 8; ++i )
        result[i + 34] = sha256_const_value_8[i];
    *result = 0;
    result[1] = 0;
}


void sha256_block_data_order(unsigned int *a1, unsigned int *a2, int len)
{

    int v3; // r2
    int v4; // r0
    int v5; // r0
    unsigned int v6; // r1
    unsigned int *v7; // r2
    unsigned int v8; // r3
    unsigned int sha_const_value_8_3; // r5
    unsigned int sha_const_value_8_4; // r6
    unsigned int sha_const_value_8_6; // r3
    unsigned int sha_const_value_8_7; // r5
    unsigned int sha_const_value_8_8; // r6
    int v14; // r6
    unsigned int v15; // r1
    unsigned int v16; // r11
    unsigned int v17; // r0
    unsigned int v18; // r10
    unsigned int v19; // r12
    unsigned int v20; // r4
    unsigned int v21; // r8
    unsigned int v22; // r3
    unsigned int v23; // lr
    unsigned int v24; // r9
    unsigned int v25; // r2
    unsigned int v26; // r12
    unsigned int v27; // r4
    unsigned int v28; // r0
    unsigned int v29; // r5
    unsigned int *v32; // [sp+4h] [bp-164h]
    int v35; // [sp+18h] [bp-150h]
    unsigned int *v36; // [sp+1Ch] [bp-14Ch]
    unsigned int v37; // [sp+20h] [bp-148h]
    unsigned int v38; // [sp+24h] [bp-144h]
    unsigned int sha_const_value_8_1; // [sp+28h] [bp-140h]
    unsigned int sha_const_value_8_2; // [sp+2Ch] [bp-13Ch]
    unsigned int v41; // [sp+30h] [bp-138h]
    unsigned int v42; // [sp+34h] [bp-134h]
    unsigned int sha_const_value_8_5; // [sp+38h] [bp-130h]
    unsigned int v46; // [sp+44h] [bp-124h]
    unsigned int v47[72]; // [sp+48h] [bp-120h] BYREF

    if (len >= 1) {
        v3 = 0;
        v32 = a1 + 34;
        do {
            v4 = 0;
            v35 = v3;
            do {
                unsigned int item = *(a2 + v4);
                v47[v4] = bswap32(item);
                ++v4;
            } while (v4 != 16);
            v36 = a2;
            v5 = 0;
            v6 = v47[0];
            do {
                v7 = &v47[v5++];
                v8 = v7[1];
                v7[16] = v6 + v7[9] + (ROR4_(v7[14], 19) ^ (v7[14] >> 10) ^ ROR4_(v7[14], 17)) + (ROR4_(v8, 18) ^ (v8 >> 3) ^ ROR4_(v8, 7));
                v6 = v8;
            } while (v5 != 48);
            sha_const_value_8_3 = a1[36];
            sha_const_value_8_4 = a1[37];
            sha_const_value_8_1 = *v32;
            sha_const_value_8_2 = a1[35];
            v41 = sha_const_value_8_3;
            v42 = sha_const_value_8_4;
            sha_const_value_8_6 = a1[39];
            sha_const_value_8_7 = a1[40];
            sha_const_value_8_8 = a1[41];
            sha_const_value_8_5 = a1[38];
            v46 = sha_const_value_8_8;
            v14 = 0;
            v38 = sha_const_value_8_1;
            v15 = sha_const_value_8_2;
            v16 = v41;
            v37 = v42;
            v17 = sha_const_value_8_7;
            v18 = sha_const_value_8_5;
            v19 = sha_const_value_8_6;
            v20 = v46;
            do {
                v21 = v17;//v21 计算正确
                v22 = v38;
                v23 = v15;
                v24 = v19;
                v25 = v18;
                v26 = v47[v14];
                v27 = v20 + sha256_const_table_64[v14++];
                v28 = (v17 & ~v18 | v24 & v18) + (ROR4_(v18, 6) ^ ROR4_(v18, 11) ^ ROR4_(v18, 25)) + v27 + v26;
                v18 = v37 + v28;
                v29 = v16;
                v37 = v16;
                v38 = v28 + (ROR4_(v38, 2) ^ ROR4_(v38, 13) ^ ROR4_(v38, 22)) + (v16 & v23 ^ (v16 ^ v23) & v38);
                v16 = v15;
                v15 = v22;
                v17 = v24;
                v19 = v25;
                v20 = v21;
            } while (v14 != 64);

            a1[34] += v38;//0
            a1[35] += v22;//1
            a1[36] += v23;//2
            a1[37] += v29;//3
            a1[38] += v18;//4
            a1[39] += v19;//5
            a1[40] += v17;//6
            a1[41] += v21;
            a2 = v36 + 16;
            v3 = v35 + 1;
        } while (v35 + 1 != len);
    }
}

void sha256_update(unsigned int *a1,unsigned char *a2, unsigned int a3)
{

//    if(a3 == 0x88){
//        printbuf(a2,200);
//    }

    unsigned int v4; // r0
    unsigned int  v7; // r6
    unsigned char *v8; // r0
    unsigned int result; // r0
    unsigned char *v10; // r8
    unsigned int  v11; // r6

    v4 = a1[1];
    v7 = 64 - v4;
    v8 = (unsigned char *) a1 + v4 + 8;
    if ( v7 > a3 )
        v7 = a3;
    memcpy(v8, a2, v7);
    result = a1[1] + a3;
    if ( result > 63 )
    {


        sha256_block_data_order(a1,a1 + 2, 1);
        v10 = &a2[v7];
        v11 = a3 - v7;
        sha256_block_data_order(a1, (unsigned int *)v10, v11 >> 6);
        memcpy(a1 + 2, &v10[v11 & 0xFFFFFFC0], v11 & 0x3F);
        a1[1] = v11 & 0x3F;
        result = *a1 + ((v11 + 64) & 0xFFFFFFC0);
        *a1 = result;
    }
    else
    {
        a1[1] = result;
    }
}

void sub_E0AC(unsigned char *outbuf,unsigned char *input_data, unsigned int input_len)
{
    unsigned char *md5_val_1; // r6
    unsigned int v5; // r5
    unsigned char *outbuf_1; // r0
    unsigned char v7; // t1

    md5_val_1 = input_data;
    if (input_len == 64 )
    {
        v5 = 64;
        LABEL_6:
        outbuf_1 = outbuf + 672;
        do
        {
            --v5;
            *outbuf_1 = *md5_val_1 ^ 0x36;
            v7 = *md5_val_1++;
            outbuf_1[64] = v7 ^ 0x5C;
            ++outbuf_1;
        }
        while ( v5 );
        goto LABEL_8;
    }
    v5 = input_len;                               // input_len = 32
    memset(&outbuf[v5 + 672], 54, 64 - v5);       // a5 = 32
    memset(&outbuf[v5 + 736], 92, 64 - v5);
    if ( v5 >= 1 )
        goto LABEL_6;
    LABEL_8:

    sha256_init((unsigned int *)outbuf);
    sha256_update((unsigned int *)outbuf, outbuf + 672, 64);
    sha256_init((unsigned int *)outbuf + 42);
    sha256_update((unsigned int *)outbuf + 42, outbuf + 736, 64);
    memcpy(outbuf + 336, outbuf, 0xA8u);
    memcpy(outbuf + 504, outbuf + 168, 0xA8u);
}


// local variable allocation has failed, the output may be wrong!
void sha256_final(unsigned int *a1,unsigned int *a2)
{
    unsigned int v3; // r9 OVERLAPPED
    unsigned int v4; // r10 OVERLAPPED
    unsigned int *v5; // r8
    int v6; // r6
    unsigned int *v8; // r0
    unsigned int *result; // r0
    int i; // r1
    unsigned char *v11; // r3

    v3 = *a1;// 就是第一个字节的数值 0x40
    v4 = a1[1];
    v5 = a1 + 2;
    v6 = 1;
    if ( (a1[1] & 0x38) == 56 )
        v6 = 2;
    memset((char *)v5 + v4, 0, (v6 << 6) - v4);
    *((unsigned char *)v5 + a1[1]) = 0x80;
    v8 = &v5[16 * v6];
    *((unsigned char *)v8 - 2) = (v3 + v4) >> 5;
    *((unsigned char *)v8 - 1) = (v3 + v4) << 3;
    *((unsigned char *)v8 - 3) = (v3 + v4) >> 13;
    *((unsigned char *)v8 - 4) = (v3 + v4) >> 21;

    sha256_block_data_order((unsigned int*)a1, (unsigned int*)v5, v6);
    result = a1 + 34;
    for ( i = 0; i != 8; ++i )
    {
        v11 = ((unsigned char *)a2 + i * 4);
        v11[0] = (result[i] & 0xff000000) >> 24;//提取高字节
        v11[1] = (result[i] & 0xff0000) >> 16;
        v11[2] = (result[i] & 0xff00) >> 8;
        v11[3] = (result[i] & 0xff);
//        printf("%#x %#x %#x %#x \n",v11[0],v11[1],v11[2],v11[3]);
    }
}

void sub_E1AC(unsigned int *a1,unsigned char *a2, size_t a3)
{
    unsigned int *v3; // r6
    unsigned int v7[36]; // [sp+0h] [bp-60h] BYREF
    unsigned int v8[32]; // [sp+24h] [bp-3Ch] BYREF
    v3 = a1;
    sha256_final(a1, v8);
    v3 += 42;
    sha256_update(v3, (unsigned char *)v8, 0x20u);
    sha256_final(v3, v7);
    memcpy(a2, v7, a3);
}


void printbuf(unsigned int *num,int size)
{
    unsigned char outbuf[1000];
    int index = 0;
    for (int i = 0; i < size; i++) {
        memcpy(outbuf+index,  &num[i],  4);
        index = index + 4;
    }

    //先输出结果buf
    printf("buf 格式化输出\n");
    for (int i = 1; i <= size*4; ++i) {
        printf("%02X ",outbuf[i-1]);
        if ( i% 16 ==0 )
            printf("\n");
    }
    printf("\n");
}

void Hex2Str(unsigned char *sSrc,unsigned  char *sDest, int length )
{
    int  i;
    char szTmp[3];
    for( i = 0; i < length; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 2], szTmp, 2 );
    }
}

void gen_salt(unsigned char *out)
{
//    unsigned char md5_str[33];
    char ts[] = "1640946695";//这个是当前时间戳，长度是10
    //下面这个值固定
    unsigned char salt[] ="LdmD9deEB8Dtp0Nluioefhli984768431C33BFDDBEDC3F28718C6FD632CCCB64";

    int new_len = strlen(ts) + strlen((char *)salt);

    memcpy(salt + strlen((char *)salt), ts, strlen(ts));
    salt[new_len] = '\0';

    unsigned char md5_encrypt_data[16];
    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5, salt, strlen((char *)salt));
    MD5Final(&md5, md5_encrypt_data);

    Hex2Str(md5_encrypt_data, out, 16);
    out[32] = '\0';
}

void gen_sign(unsigned char* data_input,unsigned char *md5_input,unsigned char *output)
{
    unsigned char tmpbuf[800];
    int data_len = strlen((char *)data_input);
    sub_E0AC(tmpbuf, md5_input, 32);
    sha256_update((unsigned int *)tmpbuf, data_input, data_len);
    sub_E1AC((unsigned int *)tmpbuf, output, 32);

}