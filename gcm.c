/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 31/01/2004

 My thanks to John Viega and David McGrew for their support in developing 
 this code and to David for testing it on a big-endain system.
*/

#include "gcm.h"

/* BUFFER_ALIGN32 or BUFFER_ALIGN64 must be defined at this point to    */
/* enable faster operation by taking advantage of memory aligned values */
/* NOTE: the BUFFER_ALIGN64 option has not been tested extensively      */

#define BUFFER_ALIGN32
#define UNROLL_LOOPS    /* define to unroll some loops      */
#define IN_LINES        /* define to use inline functions   */
                        /* in place of macros               */
#include "mode_hdr.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define CBLK_LEN   mode(BLOCK_SIZE) /* encryption block length          */
#define ABLK_LEN   mode(BLOCK_SIZE) /* authentication block length      */
#define CBLK_MASK  (CBLK_LEN - 1)   /* mask for encryption position     */
#define ABLK_MASK  (ABLK_LEN - 1)   /* mask for authentication position */

#define CTR_POS     12
#define inc_ctr(x)  \
    {   int i = CBLK_LEN; while(i-- > CTR_POS && !++(lp08(x)[i])) ; }

#define gf_dat(q) {\
    q(0x00), q(0x01), q(0x02), q(0x03), q(0x04), q(0x05), q(0x06), q(0x07),\
    q(0x08), q(0x09), q(0x0a), q(0x0b), q(0x0c), q(0x0d), q(0x0e), q(0x0f),\
    q(0x10), q(0x11), q(0x12), q(0x13), q(0x14), q(0x15), q(0x16), q(0x17),\
    q(0x18), q(0x19), q(0x1a), q(0x1b), q(0x1c), q(0x1d), q(0x1e), q(0x1f),\
    q(0x20), q(0x21), q(0x22), q(0x23), q(0x24), q(0x25), q(0x26), q(0x27),\
    q(0x28), q(0x29), q(0x2a), q(0x2b), q(0x2c), q(0x2d), q(0x2e), q(0x2f),\
    q(0x30), q(0x31), q(0x32), q(0x33), q(0x34), q(0x35), q(0x36), q(0x37),\
    q(0x38), q(0x39), q(0x3a), q(0x3b), q(0x3c), q(0x3d), q(0x3e), q(0x3f),\
    q(0x40), q(0x41), q(0x42), q(0x43), q(0x44), q(0x45), q(0x46), q(0x47),\
    q(0x48), q(0x49), q(0x4a), q(0x4b), q(0x4c), q(0x4d), q(0x4e), q(0x4f),\
    q(0x50), q(0x51), q(0x52), q(0x53), q(0x54), q(0x55), q(0x56), q(0x57),\
    q(0x58), q(0x59), q(0x5a), q(0x5b), q(0x5c), q(0x5d), q(0x5e), q(0x5f),\
    q(0x60), q(0x61), q(0x62), q(0x63), q(0x64), q(0x65), q(0x66), q(0x67),\
    q(0x68), q(0x69), q(0x6a), q(0x6b), q(0x6c), q(0x6d), q(0x6e), q(0x6f),\
    q(0x70), q(0x71), q(0x72), q(0x73), q(0x74), q(0x75), q(0x76), q(0x77),\
    q(0x78), q(0x79), q(0x7a), q(0x7b), q(0x7c), q(0x7d), q(0x7e), q(0x7f),\
    q(0x80), q(0x81), q(0x82), q(0x83), q(0x84), q(0x85), q(0x86), q(0x87),\
    q(0x88), q(0x89), q(0x8a), q(0x8b), q(0x8c), q(0x8d), q(0x8e), q(0x8f),\
    q(0x90), q(0x91), q(0x92), q(0x93), q(0x94), q(0x95), q(0x96), q(0x97),\
    q(0x98), q(0x99), q(0x9a), q(0x9b), q(0x9c), q(0x9d), q(0x9e), q(0x9f),\
    q(0xa0), q(0xa1), q(0xa2), q(0xa3), q(0xa4), q(0xa5), q(0xa6), q(0xa7),\
    q(0xa8), q(0xa9), q(0xaa), q(0xab), q(0xac), q(0xad), q(0xae), q(0xaf),\
    q(0xb0), q(0xb1), q(0xb2), q(0xb3), q(0xb4), q(0xb5), q(0xb6), q(0xb7),\
    q(0xb8), q(0xb9), q(0xba), q(0xbb), q(0xbc), q(0xbd), q(0xbe), q(0xbf),\
    q(0xc0), q(0xc1), q(0xc2), q(0xc3), q(0xc4), q(0xc5), q(0xc6), q(0xc7),\
    q(0xc8), q(0xc9), q(0xca), q(0xcb), q(0xcc), q(0xcd), q(0xce), q(0xcf),\
    q(0xd0), q(0xd1), q(0xd2), q(0xd3), q(0xd4), q(0xd5), q(0xd6), q(0xd7),\
    q(0xd8), q(0xd9), q(0xda), q(0xdb), q(0xdc), q(0xdd), q(0xde), q(0xdf),\
    q(0xe0), q(0xe1), q(0xe2), q(0xe3), q(0xe4), q(0xe5), q(0xe6), q(0xe7),\
    q(0xe8), q(0xe9), q(0xea), q(0xeb), q(0xec), q(0xed), q(0xee), q(0xef),\
    q(0xf0), q(0xf1), q(0xf2), q(0xf3), q(0xf4), q(0xf5), q(0xf6), q(0xf7),\
    q(0xf8), q(0xf9), q(0xfa), q(0xfb), q(0xfc), q(0xfd), q(0xfe), q(0xff) }

/* given the value i in 0..255 as the byte overflow when a a field  */
/* element in GHASH is multipled by x^8, this function will return  */
/* the values that are generated in the lo 16-bit word of the field */
/* value by applying the modular polynomial. The values lo_byte and */
/* hi_byte are returned via the macro xp_fun(lo_byte, hi_byte) so   */
/* that the values can be assembled into memory as required by a    */
/* suitable definition of this macro operating on the table above   */

#define xp(i) xp_fun( \
    (i & 0x80 ? 0xe1 : 0) ^ (i & 0x40 ? 0x70 : 0) ^ \
    (i & 0x20 ? 0x38 : 0) ^ (i & 0x10 ? 0x1c : 0) ^ \
    (i & 0x08 ? 0x0e : 0) ^ (i & 0x04 ? 0x07 : 0) ^ \
    (i & 0x02 ? 0x03 : 0) ^ (i & 0x01 ? 0x01 : 0),  \
    (i & 0x80 ? 0x00 : 0) ^ (i & 0x40 ? 0x80 : 0) ^ \
    (i & 0x20 ? 0x40 : 0) ^ (i & 0x10 ? 0x20 : 0) ^ \
    (i & 0x08 ? 0x10 : 0) ^ (i & 0x04 ? 0x08 : 0) ^ \
    (i & 0x02 ? 0x84 : 0) ^ (i & 0x01 ? 0xc2 : 0) )

static mode(32t) gf_poly[2] = { 0, 0xe1000000 };
static int shf_cnt[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };

/* Multiply of a GF128 field element by x.   The field element  */
/* is held in an array of bytes in which field bits 8n..8n + 7  */
/* are held in byte[n], with lower indexed bits placed in the   */
/* more numerically significant bit positions in bytes.         */

/* This function multiples a field element x, in the polynomial */
/* field representation. It uses 32-bit word operations to gain */
/* speed but compensates for machine endianess and hence works  */
/* correctly on both styles of machine                          */

in_line void mul_x(mode(32t) x[4])
{   mode(32t)   t;

    bsw_32(x, 4);

    /* at this point the filed element bits 0..127 are set out  */
    /* as follows in 32-bit words (where the most significant   */
    /* (ms) numeric bits are to the left)                       */
    /*                                                          */
    /*            x[0]      x[1]      x[2]      x[3]            */
    /*          ms    ls  ms    ls  ms    ls  ms     ls         */
    /* field:   0 ... 31  32 .. 63  64 .. 95  96 .. 127         */

    t = gf_poly[x[3] & 1];          /* bit 127 of the element   */
    x[3] = (x[3] >> 1) | (x[2] << 31);  /* shift bits up by one */
    x[2] = (x[2] >> 1) | (x[1] << 31);  /* position             */
    x[1] = (x[1] >> 1) | (x[0] << 31);  /* if bit 7 is 1 xor in */
    x[0] = (x[0] >> 1) ^ t;             /* the field polynomial */
    bsw_32(x, 4);
}

/* Multiply of a GF128 field element by x^8 using 32-bit words  */
/* for speed - machine endianess matters here                   */

#if (PLATFORM_BYTE_ORDER == BRG_LITTLE_ENDIAN)

#define xp_fun(x,y)    ((mode(32t))(x)) | (((mode(32t))(y)) << 8)
static const unsigned short gft_le[256] = gf_dat(xp);

in_line void mul_lex8(mode(32t) x[4])   /* mutiply with long words  */
{   mode(32t)   t = (x[3] >> 24);       /* in little endian format  */
    x[3] = (x[3] << 8) | (x[2] >> 24);
    x[2] = (x[2] << 8) | (x[1] >> 24);
    x[1] = (x[1] << 8) | (x[0] >> 24);
    x[0] = (x[0] << 8) ^ gft_le[t];
}

#endif

#if 1 || (PLATFORM_BYTE_ORDER == BRG_LITTLE_ENDIAN)

#undef  xp_fun
#define xp_fun(x,y)    ((mode(32t))(y)) | (((mode(32t))(x)) << 8)
static const unsigned short gft_be[256] = gf_dat(xp);

in_line void mul_bex8(mode(32t) x[4])   /* mutiply with long words  */
{   mode(32t)   t = (x[3] & 0xff);      /* in big endian format     */
    x[3] = (x[3] >> 8) | (x[2] << 24);
    x[2] = (x[2] >> 8) | (x[1] << 24);
    x[1] = (x[1] >> 8) | (x[0] << 24);
    x[0] = (x[0] >> 8) ^ (((mode(32t))gft_be[t]) << 16);
}

#endif

/* hence choose the correct version for the machine endianess       */

#if PLATFORM_BYTE_ORDER == BRG_BIG_ENDIAN
#define mul_x8  mul_bex8
#else
#define mul_x8  mul_lex8
#endif

/* different versions of the general gf_mul function are provided   */
/* here. Sadly none are very fast :-(                               */

#if 1

void gf_mul(void *a, const void* b)
{   mode(32t) r[CBLK_LEN >> 2], p[8][CBLK_LEN >> 2];
    int i;

    move_block_aligned(p[0], b);
    bsw_32(p[0], 4);
    for(i = 0; i < 7; ++i)
    {
        p[i + 1][3] = (p[i][3] >> 1) | (p[i][2] << 31);
        p[i + 1][2] = (p[i][2] >> 1) | (p[i][1] << 31);
        p[i + 1][1] = (p[i][1] >> 1) | (p[i][0] << 31);
        p[i + 1][0] = (p[i][0] >> 1) ^ gf_poly[p[i][3] & 1];
    }

    memset(r, 0, CBLK_LEN);
    for(i = 0; i < 16; ++i)
    {
        if(i) mul_bex8(r);  /* order is always big endian here */

        if(((unsigned char*)a)[15 - i] & 0x80)
            xor_block_aligned(r, p[0]);
        if(((unsigned char*)a)[15 - i] & 0x40)
            xor_block_aligned(r, p[1]);
        if(((unsigned char*)a)[15 - i] & 0x20)
            xor_block_aligned(r, p[2]);
        if(((unsigned char*)a)[15 - i] & 0x10)
            xor_block_aligned(r, p[3]);
        if(((unsigned char*)a)[15 - i] & 0x08)
            xor_block_aligned(r, p[4]);
        if(((unsigned char*)a)[15 - i] & 0x04)
            xor_block_aligned(r, p[5]);
        if(((unsigned char*)a)[15 - i] & 0x02)
            xor_block_aligned(r, p[6]);
        if(((unsigned char*)a)[15 - i] & 0x01)
            xor_block_aligned(r, p[7]);
    }
    bsw_32(r, 4);
    move_block_aligned(a, r);
}

#elif 0

void gf_mul(void *a, const void* b)
{   mode(32t) r[CBLK_LEN >> 2], p[8][CBLK_LEN >> 2];
    int i;

    move_block_aligned(p[0], b);
    move_block_aligned(p[1], p[0]); mul_x(p[1]);
    move_block_aligned(p[2], p[1]); mul_x(p[2]);
    move_block_aligned(p[3], p[2]); mul_x(p[3]);
    move_block_aligned(p[4], p[3]); mul_x(p[4]);
    move_block_aligned(p[5], p[4]); mul_x(p[5]);
    move_block_aligned(p[6], p[5]); mul_x(p[6]);
    move_block_aligned(p[7], p[6]); mul_x(p[7]);

    memset(r, 0, CBLK_LEN);
    for(i = 0; i < 16; ++i)
    {
        if(i) mul_x8(r);

        if(((unsigned char*)a)[15 - i] & 0x80)
            xor_block_aligned(r, p[0]);
        if(((unsigned char*)a)[15 - i] & 0x40)
            xor_block_aligned(r, p[1]);
        if(((unsigned char*)a)[15 - i] & 0x20)
            xor_block_aligned(r, p[2]);
        if(((unsigned char*)a)[15 - i] & 0x10)
            xor_block_aligned(r, p[3]);
        if(((unsigned char*)a)[15 - i] & 0x08)
            xor_block_aligned(r, p[4]);
        if(((unsigned char*)a)[15 - i] & 0x04)
            xor_block_aligned(r, p[5]);
        if(((unsigned char*)a)[15 - i] & 0x02)
            xor_block_aligned(r, p[6]);
        if(((unsigned char*)a)[15 - i] & 0x01)
            xor_block_aligned(r, p[7]);
    }
    move_block_aligned(a, r);
}

#elif 0

void gf_mul(void *a, const void* b)
{   mode(32t) r[CBLK_LEN >> 2], p[CBLK_LEN >> 2], t;
    int i, j;

    memset(r, 0, CBLK_LEN);
    move_block_aligned(p, b);
    bsw_32(p, 4);
    for(i = 0; i < 16; ++i)
        for(j = 0; j < 8; ++j)
        {
            t = gf_poly[r[3] & 1];
            r[3] = (r[3] >> 1) | (r[2] << 31);
            r[2] = (r[2] >> 1) | (r[1] << 31);
            r[1] = (r[1] >> 1) | (r[0] << 31);
            r[0] = (r[0] >> 1) ^ t;
            if(((unsigned char*)a)[15 - i] & shf_cnt[7 - j])
                xor_block_aligned(r, p);
        }
    bsw_32(r, 4);
    move_block_aligned(a, r);
}

#else

void gf_mul(void *a, const void* b)
{   mode(32t) r[CBLK_LEN >> 2], p[CBLK_LEN >> 2], t;
    int i, j;

    memset(r, 0, CBLK_LEN);
    move_block_aligned(p, b);
    bsw_32(p, 4);
    for(i = 0; i < 16; ++i)
        for(j = 0; j < 8; ++j)
        {
            if(((unsigned char*)a)[i] & shf_cnt[j])
                xor_block_aligned(r, p);

            t = gf_poly[p[3] & 1];
            p[3] = (p[3] >> 1) | (p[2] << 31);
            p[2] = (p[2] >> 1) | (p[1] << 31);
            p[1] = (p[1] >> 1) | (p[0] << 31);
            p[0] = (p[0] >> 1) ^ t;
        }

    bsw_32(r, 4);
    move_block_aligned(a, r);
}

#endif

#if defined( TABLES_64K )   /* this version uses 64k bytes  */
                            /* of table space on the stack  */
#if defined( UNROLL_LOOPS )

#define xor_64k(i)  xor_block_aligned(r, ctx->gf_t64k[i][a[i]]);

void gf_mul_h(unsigned char a[CBLK_LEN], mode(ctx) ctx[1])
{   mode(32t)   r[CBLK_LEN >> 2];

    move_block_aligned(r, ctx->gf_t64k[0][a[0]]);
                 xor_64k( 1); xor_64k( 2); xor_64k( 3);
    xor_64k( 4); xor_64k( 5); xor_64k( 6); xor_64k( 7);
    xor_64k( 8); xor_64k( 9); xor_64k(10); xor_64k(11);
    xor_64k(12); xor_64k(13); xor_64k(14); xor_64k(15);
    move_block_aligned(a, r);
}

#else

void gf_mul_h(unsigned char a[CBLK_LEN], mode(ctx) ctx[1])
{   mode(32t)   r[CBLK_LEN >> 2];
    int         i;

    move_block_aligned(r, ctx->gf_t64k[0][a[0]]);
    for(i = 1; i < CBLK_LEN; ++i)
        xor_block_aligned(r,ctx->gf_t64k[i][a[i]]);
    move_block_aligned(a, r);
}

#endif

void compile_64k_table(mode(ctx) ctx[1])
{   int i, j, k;

    memset(ctx->gf_t64k, 0, 16 * 256 * 16);
    for(i = 0; i < CBLK_LEN; ++i)
    {
        if(!i)
        {
            memcpy(ctx->gf_t64k[0][128], ctx->ghash_h, CBLK_LEN);
            for(j = 64; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t64k[0][j], ctx->gf_t64k[0][j + j], CBLK_LEN);
                mul_x(ctx->gf_t64k[0][j]);
            }
        }
        else
            for(j = 128; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t64k[i][j], ctx->gf_t64k[i - 1][j], CBLK_LEN);
                mul_x8(ctx->gf_t64k[i][j]);
            }

        for(j = 2; j < 256; j += j)
        {
            mode(32t) *pj = ctx->gf_t64k[i][j];
            mode(32t) *pk = ctx->gf_t64k[i][1];
            mode(32t) *pl = ctx->gf_t64k[i][j + 1];

            for(k = 1; k < j; ++k)
            {
                *pl++ = pj[0] ^ *pk++;
                *pl++ = pj[1] ^ *pk++;
                *pl++ = pj[2] ^ *pk++;
                *pl++ = pj[3] ^ *pk++;
            }
        }
    }
}

#endif

#if defined( TABLES_8K )    /* this version uses 8k bytes   */
                            /* of table space on the stack  */
#if defined( UNROLL_LOOPS )

#define xor_8k(i)   \
    xor_block_aligned(r, ctx->gf_t8k[i + i][a[i] & 15]); \
    xor_block_aligned(r, ctx->gf_t8k[i + i + 1][a[i] >> 4])

void gf_mul_h(unsigned char a[CBLK_LEN], mode(ctx) ctx[1])
{   unsigned long r[CBLK_LEN >> 2], *p;

    move_block_aligned(r, ctx->gf_t8k[0][a[0] & 15]);
    xor_block_aligned(r, ctx->gf_t8k[1][a[0] >> 4]);
                xor_8k( 1); xor_8k( 2); xor_8k( 3);
    xor_8k( 4); xor_8k( 5); xor_8k( 6); xor_8k( 7);
    xor_8k( 8); xor_8k( 9); xor_8k(10); xor_8k(11);
    xor_8k(12); xor_8k(13); xor_8k(14); xor_8k(15);
    move_block_aligned(a, r);
}

#else

void gf_mul_h(unsigned char a[CBLK_LEN], mode(ctx) ctx[1])
{   unsigned long r[CBLK_LEN >> 2], *p;
    int i;

    p = ctx->gf_t8k[0][a[0] & 15];
    memcpy(r, p, CBLK_LEN);
    p = ctx->gf_t8k[1][a[0] >> 4];
    xor_block_aligned(r, p);
    for(i = 1; i < CBLK_LEN; ++i)
    {
        xor_block_aligned(r, ctx->gf_t8k[i + i][a[i] & 15]);
        xor_block_aligned(r, ctx->gf_t8k[i + i + 1][a[i] >> 4]);
    }
    memcpy(a, r, CBLK_LEN);
}

#endif

void compile_8k_table(mode(ctx) ctx[1])
{   int i, j, k;

    memset(ctx->gf_t8k, 0, 32 * 16 * 16);
    for(i = 0; i < 2 * CBLK_LEN; ++i)
    {
        if(i == 0)
        {
            memcpy(ctx->gf_t8k[1][8], ctx->ghash_h, CBLK_LEN);
            for(j = 4; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t8k[1][j], ctx->gf_t8k[1][j + j], CBLK_LEN);
                mul_x(ctx->gf_t8k[1][j]);
            }
            memcpy(ctx->gf_t8k[0][8], ctx->gf_t8k[1][1], CBLK_LEN);
            mul_x(ctx->gf_t8k[0][8]);
            for(j = 4; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t8k[0][j], ctx->gf_t8k[0][j + j], CBLK_LEN);
                mul_x(ctx->gf_t8k[0][j]);
            }
        }
        else if(i > 1)
            for(j = 8; j > 0; j >>= 1)
            {
                memcpy(ctx->gf_t8k[i][j], ctx->gf_t8k[i - 2][j], CBLK_LEN);
                mul_x8(ctx->gf_t8k[i][j]);
            }

        for(j = 2; j < 16; j += j)
        {
            mode(32t) *pj = ctx->gf_t8k[i][j];
            mode(32t) *pk = ctx->gf_t8k[i][1];
            mode(32t) *pl = ctx->gf_t8k[i][j + 1];

            for(k = 1; k < j; ++k)
            {
                *pl++ = pj[0] ^ *pk++;
                *pl++ = pj[1] ^ *pk++;
                *pl++ = pj[2] ^ *pk++;
                *pl++ = pj[3] ^ *pk++;
            }
        }
    }
}

#endif

#if defined( TABLES_4K )    /* this version uses 4k bytes   */
                            /* of table space on the stack  */

void gf_mul_h(unsigned char a[CBLK_LEN], mode(ctx) ctx[1])
{   mode(32t)   r[CBLK_LEN >> 2];

    move_block_aligned(r, ctx->gf_t4k[a[15]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[14]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[13]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[12]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[11]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[10]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 9]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 8]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 7]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 6]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 5]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 4]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 3]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 2]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 1]]); mul_x8(r);
    xor_block_aligned(r, ctx->gf_t4k[a[ 0]]);
    move_block_aligned(a, r);
}

void compile_4k_table(mode(ctx) ctx[1])
{   int j, k;

    memset(ctx->gf_t4k, 0, 256 * 16);
    memcpy(ctx->gf_t4k[128], ctx->ghash_h, CBLK_LEN);
    for(j = 64; j > 0; j >>= 1)
    {
        memcpy(ctx->gf_t4k[j], ctx->gf_t4k[j + j], CBLK_LEN);
        mul_x(ctx->gf_t4k[j]);
    }

    for(j = 2; j < 256; j += j)
    {
        mode(32t) *pj = ctx->gf_t4k[j];
        mode(32t) *pk = ctx->gf_t4k[1];
        mode(32t) *pl = ctx->gf_t4k[j + 1];

        for(k = 1; k < j; ++k)
        {
            *pl++ = pj[0] ^ *pk++;
            *pl++ = pj[1] ^ *pk++;
            *pl++ = pj[2] ^ *pk++;
            *pl++ = pj[3] ^ *pk++;
        }
    }
}

#endif

#if !defined( TABLES_8K ) && !defined( TABLES_64K ) && !defined( TABLES_4K )

/* this is a very slow version without tables   */

void gf_mul_h(unsigned char a[CBLK_LEN], mode(ctx) ctx[1])
{
    gf_mul(a, ctx->ghash_h);
}

#endif

ret_type mode(init_and_key)(            /* initialise mode and set key          */
            const unsigned char key[],          /* the key value                */
            unsigned long key_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    /* set the context to all zeroes            */
    memset(ctx, 0, sizeof(mode(ctx)));

    /* set the AES key                          */
    aes_encrypt_key(key, key_len, ctx->aes);

    /* compute E(0) (for the hash function)     */
    aes_encrypt(ctx->ghash_h, ctx->ghash_h, ctx->aes);

#if defined( TABLES_64K )
    compile_64k_table(ctx);
#endif
#if defined( TABLES_8K )
    compile_8k_table(ctx);
#endif
#if defined( TABLES_4K )
    compile_4k_table(ctx);
#endif
    return SUCCESS;
}

ret_type mode(init_message)(            /* initialise for a message operation   */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long n_pos = 0;
    unsigned char   *p;
    unsigned int i;

    if(iv_len == CTR_POS)
    {
        memcpy(ctx->ctr_val, iv, CTR_POS); ctx->ctr_val[15] = 0x01;
    }
    else
    {   n_pos = iv_len;
        while(n_pos >= CBLK_LEN)
        {
            xor_block_aligned(ctx->ctr_val, iv);
            n_pos -= CBLK_LEN;
            iv += CBLK_LEN;
            gf_mul_h(ctx->ctr_val, ctx);
        }

        p = ctx->ctr_val;
        while(n_pos-- > 0)
            *p++ ^= *iv++;
        gf_mul_h(ctx->ctr_val, ctx);
        n_pos = (iv_len << 3);
        for(i = CBLK_LEN - 1; n_pos; --i, n_pos >>= 8)
            ctx->ctr_val[i] ^= (unsigned char)n_pos;
        gf_mul_h(ctx->ctr_val, ctx);
    }

    ctx->y0_val = *(unsigned long*)(ctx->ctr_val + CTR_POS);
    i = CBLK_LEN;
    while(i-- > CTR_POS && !++(ctx->ctr_val[i]))
        ;
    aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
    memset(ctx->hdr_ghv, 0, CBLK_LEN);
    memset(ctx->txt_ghv, 0, CBLK_LEN);
    ctx->hdr_cnt = 0;
    ctx->txt_ccnt = ctx->txt_acnt = 0;
    return SUCCESS;
}

ret_type mode(auth_header)(             /* authenticate the message header      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = (unsigned long)ctx->hdr_cnt & ABLK_MASK;

    if(!hdr_len) return SUCCESS;

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < hdr_len)
            lp08(ctx->hdr_ghv)[b_pos++] ^= hdr[cnt++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((hdr + cnt - lp08(ctx->hdr_ghv)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            {
                *lp(lp08(ctx->hdr_ghv) + b_pos) ^= *lp(hdr + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= hdr_len)
            {
                gf_mul_h(ctx->hdr_ghv, ctx);
                xor_block_aligned(ctx->hdr_ghv, hdr + cnt);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            lp08(ctx->hdr_ghv)[b_pos++] ^= hdr[cnt++];

        while(cnt + ABLK_LEN <= hdr_len)
        {
            gf_mul_h(ctx->hdr_ghv, ctx);
            xor_block(ctx->hdr_ghv, hdr + cnt);
            cnt += ABLK_LEN;
            b_pos = ABLK_LEN;
        }
    }

    while(cnt < hdr_len)
    {
        if(b_pos == ABLK_LEN)
        {
            gf_mul_h(ctx->hdr_ghv, ctx);
            b_pos = 0;
        }
        lp08(ctx->hdr_ghv)[b_pos++] ^= hdr[cnt++];
    }

    if(b_pos == ABLK_LEN)
        gf_mul_h(ctx->hdr_ghv, ctx);

    ctx->hdr_cnt += cnt;
    return SUCCESS;
}

ret_type mode(auth_data)(               /* authenticate ciphertext data         */
            const unsigned char data[],         /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = (unsigned long)ctx->txt_acnt & ABLK_MASK;

    if(!data_len) return SUCCESS;

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < data_len)
            lp08(ctx->txt_ghv)[b_pos++] ^= data[cnt++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((data + cnt - lp08(ctx->txt_ghv)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= data_len && b_pos < ABLK_LEN)
            {
                *lp(lp08(ctx->txt_ghv) + b_pos) ^= *lp(data + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= data_len)
            {
                gf_mul_h(ctx->txt_ghv, ctx);
                xor_block_aligned(ctx->txt_ghv, data + cnt);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + ABLK_LEN <= data_len && b_pos < ABLK_LEN)
            lp08(ctx->txt_ghv)[b_pos++] ^= data[cnt++];

        while(cnt + ABLK_LEN <= data_len)
        {
            gf_mul_h(ctx->txt_ghv, ctx);
            xor_block(ctx->txt_ghv, data + cnt);
            cnt += ABLK_LEN;
            b_pos = ABLK_LEN;
        }
    }

    while(cnt < data_len)
    {
        if(b_pos == ABLK_LEN)
        {
            gf_mul_h(ctx->txt_ghv, ctx);
            b_pos = 0;
        }
        lp08(ctx->txt_ghv)[b_pos++] ^= data[cnt++];
    }

    if(b_pos == ABLK_LEN)
        gf_mul_h(ctx->txt_ghv, ctx);

    ctx->txt_acnt += cnt;
    return SUCCESS;
}

ret_type mode(crypt_data)(              /* decrypt ciphertext data              */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = (unsigned long)ctx->txt_ccnt & CBLK_MASK;

    if(!data_len) return SUCCESS;

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < data_len)
            data[cnt++] ^= lp08(ctx->enc_ctr)[b_pos++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((data + cnt - lp08(ctx->enc_ctr)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + CBLK_LEN <= data_len && b_pos < CBLK_LEN)
            {
                *lp(data + cnt) ^= *lp(lp08(ctx->enc_ctr) + b_pos);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + CBLK_LEN <= data_len)
            {
                inc_ctr(ctx->ctr_val);
                aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
                xor_block_aligned(data + cnt, ctx->enc_ctr);
                cnt += CBLK_LEN;
                b_pos = CBLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + CBLK_LEN <= data_len && b_pos < CBLK_LEN)
            data[cnt++] ^= lp08(ctx->enc_ctr)[b_pos++];

        while(cnt + CBLK_LEN <= data_len)
        {
            inc_ctr(ctx->ctr_val);
            aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
            xor_block(data + cnt, ctx->enc_ctr);
            cnt += CBLK_LEN;
            b_pos = CBLK_LEN;
        }
    }

    while(cnt < data_len)
    {
        if(b_pos == CBLK_LEN)
        {
            inc_ctr(ctx->ctr_val);
            aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
            b_pos = 0;
        }
        data[cnt++] ^= lp08(ctx->enc_ctr)[b_pos++];
    }

    ctx->txt_ccnt += cnt;
    return SUCCESS;
}

ret_type mode(compute_tag)(             /* compute message authentication tag   */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long ln;
    unsigned int i;
    unsigned char tbuf[CBLK_LEN];

    if(ctx->hdr_cnt & CBLK_MASK)
        gf_mul_h(ctx->hdr_ghv, ctx);

    if(ctx->txt_acnt & CBLK_MASK)
        gf_mul_h(ctx->txt_ghv, ctx);

    if(ctx->hdr_cnt && (ln = (unsigned long)((ctx->txt_ccnt + CBLK_LEN - 1)
                        / CBLK_LEN)))
    {
        memcpy(tbuf, ctx->ghash_h, CBLK_LEN);
        for( ; ; )
        {
            if(ln & 1) gf_mul(ctx->hdr_ghv, tbuf);
            if(!(ln >>= 1)) break;
            gf_mul(tbuf, tbuf);
        }
    }

    i = CBLK_LEN; ln = (unsigned long)(ctx->txt_ccnt << 3);
    while(i-- > 0)
    {
        ctx->hdr_ghv[i] ^= ctx->txt_ghv[i] ^ (unsigned char)ln;
        ln = (i == 8 ? (unsigned long)(ctx->hdr_cnt << 3) : ln >> 8);
    }

    gf_mul_h(ctx->hdr_ghv, ctx);

    *(unsigned long*)(ctx->ctr_val + CTR_POS) = ctx->y0_val;
    aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
    for(i = 0; i < (unsigned int)tag_len; ++i)
        tag[i] = ctx->hdr_ghv[i] ^ ctx->enc_ctr[i];
    return SUCCESS;
}

ret_type mode(end)(                     /* clean up and end operation           */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    memset(ctx, 0, sizeof(mode(ctx)));
    return SUCCESS;
}

ret_type mode(encrypt)(                 /* encrypt and authenticate data        */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{

    mode(crypt_data)(data, data_len, ctx);
    mode(auth_data)(data, data_len, ctx);
    return SUCCESS;
}

ret_type mode(decrypt)(                 /* authenticate and decrypt data        */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    mode(auth_data)(data, data_len, ctx);
    mode(crypt_data)(data, data_len, ctx);
    return SUCCESS;
}

ret_type mode(encrypt_message)(         /* encrypt an entire message            */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            unsigned char msg[],                /* the message buffer           */
            unsigned long msg_len,              /* and its length in bytes      */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    mode(init_message)(iv, iv_len, ctx);
    mode(auth_header)(hdr, hdr_len, ctx);
    mode(encrypt)(msg, msg_len, ctx);
    mode(compute_tag)(tag, tag_len, ctx);
    return SUCCESS;
}

ret_type mode(decrypt_message)(         /* decrypt an entire message            */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            unsigned char msg[],                /* the message buffer           */
            unsigned long msg_len,              /* and its length in bytes      */
            const unsigned char tag[],          /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned char local_tag[CBLK_LEN];

    mode(init_message)(iv, iv_len, ctx);
    mode(auth_header)(hdr, hdr_len, ctx);
    mode(decrypt)(msg, msg_len, ctx);
    mode(compute_tag)(local_tag, tag_len, ctx);
    return memcmp(tag, local_tag, tag_len) ? FAILURE : SUCCESS;
}

#if defined(__cplusplus)
}
#endif
