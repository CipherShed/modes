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
 Issue Date: 26/08/2003

 This file contains the code for implementing encryption and authentication
 using AES with a Carter-Wegamn hash function.  Note that it uses Microsoft
 calls to set the FPU into specific operating conditions
*/

#include "cwc.h"

#define BUFFER_ALIGN32
#define IN_LINES

#include "mode_hdr.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define CBLK_LEN	mode(CBLK_SIZE)
#define ABLK_LEN	mode(ABLK_SIZE)
#define CBLK_MASK  (CBLK_LEN - 1)

#define be_inc(x,n) !++((x)[n+3]) && !++((x)[n+2]) && !++((x)[n+1]) &&  ++((x)[n])
#define le_inc(x,n) !++((x)[n]) && !++((x)[n+1]) && !++((x)[n+2]) &&  ++((x)[n+3])

/* define an unsigned 32-bit type */

#if defined( USE_FLOATS )

#include <float.h>

/*
    Floating Point Unit Control

    _MCW_RC     Rounding Control Mask
    _RC_NEAR    near
    _RC_DOWN    down
    _RC_UP      up
    _RC_CHOP    chop

    _MCW_PC     Precision Control Mask
    _PC_64      64 bits
    _PC_53      53 bits
    _PC_24      24 bits

    Note this only conrols the normal FPU - special intrinsics are needed
    to control the SSE/SSE2 FPU
*/

/* set to 53 bit precision and truncate towards zero */
#define set_FPU     _controlfp(_PC_53 | _RC_CHOP, _MCW_PC | _MCW_RC)

/* set to default state                             */
#define reset_FPU   _controlfp(CW_DEFAULT, 0xffff);

/*
    The main cost in CWC hash calculation is in multiplying two 127 bit
    numbers mod 2^127-1. This can be implemented quite efficiently using
    floating point operations by splitting the two values into 24 bit
    chunks so that product terms are 48 bits and sums of product terms
    still fit into 53 bit double precision values. If b is 2^24 we have:

        x = x[5]*b^5 + x[4]*b^4 + x[3]*b^3 + x[2]*b^2 + x[1]*b + x[0]
        z = z[5]*b^5 + z[4]*b^4 + z[3]*b^3 + z[2]*b^2 + z[1]*b + z[0]

    with the product terms:

        r[ 0] = (x[0] * z[0])
        r[ 1] = (x[0] * z[1] + x[1] * z[0]) * b
        ......
        r[ 9] = (x[4] * z[5] + x[5] * z[4]) * b^9
        r[10] = (x[5] * z[5]) * b ^ 10

    Now we need to compute the modulus of each term mod 2^127 - 1. so
    using the r[9] term (= v * b^9) as an example we can calculate:

        b^9 = (2^24)^9 = 2^216 = 2^127 * 2^89 = 2^127 * b^3 * 2^17

        v * b^9 = 2^127 * v * b^3 * 2^17
                = (2^127 - 1) * v * b^3 * 2^17 + b^3 * (2^17 * v)

        (v * b^9) mod (2^127 - 1) = (2^17 * v) * b^3;

    So we can account for this term in the result by adding an extra
    value to the r[3] term.

    But v is a 48 bit value and we are adding 17 more bits with the
    2^17 term so the result will overflow 53 bit arithmetic. So we
    must split the result so that

        (2^17 * v) * b^3 = v_hi * b^4 + v_lo * b^3

    and add the low part to r[3] and the high part to r[4]. We hence
    need the low 7 bits of v for v_lo and the high bits for v_hi

    When the low bit of a 53 bit floating point number represents
    the value 2^n the high bit represents 2^(52 + n) so if the low
    bit represents 2^7 the high bit represents 2^59.  So if we take
    a number below 2^59 and add 2^59 to it we know that all bits
    that represent values below 2^7 will be lost (however we must
    ensure that the result is truncated and not rounded). So if we
    do the computations

            top = (v + 2^59) - 2^59
            bot = v - top;

    we have
            2^17 * v = 2^17 * (top + bot)
                     = 2^24 * (2^-7 * top) + (2^17 * bot)
    and
            v_hi = 2^-7 * top and v_lo = 2^17 * bot

    We can do the same calculations for r[6] to r[10]. For r[5] we
    need to represent it as:

        r[5] * b^5 = 2^120 * v = 2^127 * v_hi + 2^120 * v_lo
        r[5] mod (2^127 - 1) = v_lo * b^5 + v_hi

    where v_hi and v_lo are extracted as described above. We
    then set r[5] from v_lo and add v_hi to r[0].

    We have now got the values into r[0] to r[5] but they
    are 48+ bit values that are offset by 24 bits as follows:

        r[0]                              xxxxxxxxxxxx
        r[1]                        xxxxxxxxxxxx
        r[2]                  xxxxxxxxxxxx
        .....

    To get the 24 bit components we must hence carry the top
    24+ bits of r[i] into r[i + 1] or i = 0..4. In this case
    the values are split using (v + 2^76) - 2^76).

    When we ripple the carries through like this we may find
    that r[5] is larger than 2^127 - 1, in which case we have
    to reduce r[5] once more.  This might produce more carries
    so if we want all results to fit in 24 bits we may have to
    repeat the carry process.

    However it turns out that we can work the next iteration of
    the product without insisting that the top 29 bits of all
    values are zero.  These values only have to be small enough
    to ensure that the sums of product terms in the next steps
    don't overflow 53 bits.

    Bernstein calls a reduction that ensures that the top 29
    bits of all values are zero a 'freeze' operation. If the
    resulting 'carries' are small, but not necessarily zero,
    he calls the operation a 'squeeze'.

    In fact the carry operations can be performed in many
    different orders and this freedom can be used to optimise
    the calculation. For more details see Daniel Bernstein's
    paper "Floating Point Arithmetic and Message Authentication"
    in the Journal of Cryptology (submitted in March 2000).
*/

static double   tm24 = 1.0 / (65536.0 * 256.0);
static double   tm07 = 2.0 / 256.0;
static double   tp17 = 2.0 * 65536.0;
static double   tp59 = 2048.0 * 65536.0 * 65536.0 * 65536.0;
static double   tp76 = 4096.0 * 65536.0 * 65536.0 * 65536.0 * 65536.0;

/* reduce a value to its canonical form */

void freeze(double h[], int full)
{   double  f, p;

    p = h[0];
    f = (p + tp76) - tp76;
    h[0] = p - f;
    p = h[1] += tm24 * f;
    f = (p + tp76) - tp76;
    h[1] = p - f;
    p = h[2] += tm24 * f;
    f = (p + tp76) - tp76;
    h[2] = p - f;
    p = h[3] += tm24 * f;
    f = (p + tp76) - tp76;
    h[3] = p - f;
    p = h[4] += tm24 * f;
    f = (p + tp76) - tp76;
    h[4] = p - f;
    h[5] += tm24 * f;

    /* do modular reduction step    */
    /* if the value must be fully   */
    /* canonical then ripple any    */
    /* new carries produced by the  */
    /* modular reduction step       */
    if((f = ((h[5] + tp59) - tp59)) != 0.0)
    {   int i = 0;

        h[0] += tm07 * f; h[5] -= f;

        if(full)
            while(i < 5 && (f = ((h[i] + tp76) - tp76)) != 0.0)
            {
                h[i] -= f;
                h[++i] += tm24 * f;
            }
    }
}

/* There are two implementations of cwc to choose from  */

#if 1

void do_cwc(unsigned long in[], mode(ctx) ctx[1])
{   unsigned long   data[3];
    double  a[6], v, f, p;

    data[2] = bswap_32(in[2]);
    data[1] = bswap_32(in[1]);
    data[0] = bswap_32(in[0]);

    /* split input data into 24 bit double values   */
    a[0] =  data[2] & 0x00ffffff;
    a[1] = (data[2] >> 24) | ((data[1] & 0x0000ffff) << 8);
    a[2] = (data[1] >> 16) | ((data[0] & 0x000000ff) << 16);
    a[3] =  data[0] >> 8;

    /* add into the running hash value              */
    a[0] += ctx->hash[0]; a[1] += ctx->hash[1];
    a[2] += ctx->hash[2]; a[3] += ctx->hash[3];
    a[4] = ctx->hash[4]; a[5] = ctx->hash[5];

    /* calculate the low five terms of the product  */
    ctx->hash[0] = a[0] * ctx->zval[0];
    ctx->hash[1] = a[1] * ctx->zval[0]
                 + a[0] * ctx->zval[1];
    ctx->hash[2] = a[2] * ctx->zval[0]
                 + a[1] * ctx->zval[1]
                 + a[0] * ctx->zval[2];
    ctx->hash[3] = a[3] * ctx->zval[0]
                 + a[2] * ctx->zval[1]
                 + a[1] * ctx->zval[2]
                 + a[0] * ctx->zval[3];
    ctx->hash[4] = a[4] * ctx->zval[0]
                 + a[3] * ctx->zval[1]
                 + a[2] * ctx->zval[2]
                 + a[1] * ctx->zval[3]
                 + a[0] * ctx->zval[4];
    ctx->hash[5] = a[5] * ctx->zval[0]
                 + a[4] * ctx->zval[1]
                 + a[3] * ctx->zval[2]
                 + a[2] * ctx->zval[3]
                 + a[1] * ctx->zval[4]
                 + a[0] * ctx->zval[5];

    v = a[5] * ctx->zval[5];    /* add in r[10] term */
    f = (v + tp59) - tp59;
    ctx->hash[4] += tp17 * (v - f);
    ctx->hash[5] += tm07 * f;

    f = (ctx->hash[5] + tp59) - tp59;
    ctx->hash[5] -= f;          /* modular reduction */
    ctx->hash[0] += tm07 * f;

    v = a[5] * ctx->zval[1]
      + a[4] * ctx->zval[2]
      + a[3] * ctx->zval[3]
      + a[2] * ctx->zval[4]
      + a[1] * ctx->zval[5];    /* add in r[6] term  */
    f = (v + tp59) - tp59;
    p = ctx->hash[0] + tp17 * (v - f);
    v = (p + tp76) - tp76;
    ctx->hash[0] = p - v;
    ctx->hash[1] += tm07 * f + tm24 * v;

    v = a[5] * ctx->zval[2]
      + a[4] * ctx->zval[3]
      + a[3] * ctx->zval[4]
      + a[2] * ctx->zval[5];    /* add in r[7] term  */
    f = (v + tp59) - tp59;
    p = ctx->hash[1] + tp17 * (v - f);
    v = (p + tp76) - tp76;
    ctx->hash[1] = p - v;
    ctx->hash[2] += tm07 * f + tm24 * v;

    v = a[5] * ctx->zval[3]
      + a[4] * ctx->zval[4]
      + a[3] * ctx->zval[5];    /* add in r[8] term  */
    f = (v + tp59) - tp59;
    p = ctx->hash[2] + tp17 * (v - f);
    v = (p + tp76) - tp76;
    ctx->hash[2] = p - v;
    ctx->hash[3] += tm07 * f + tm24 * v;

    v = a[5] * ctx->zval[4]
      + a[4] * ctx->zval[5];    /* add in r[9] term  */
    f = (v + tp59) - tp59;
    p = ctx->hash[3] + tp17 * (v - f);
    v = (p + tp76) - tp76;
    ctx->hash[3] = p - v;
    ctx->hash[4] += tm07 * f + tm24 * v;

    f = (ctx->hash[4] + tp76) - tp76;
    ctx->hash[4] -= f;
    ctx->hash[5] += tm24 * f;
}

#else

void do_cwc(unsigned long in[], mode(ctx) ctx[1])
{   unsigned long   data[3];
    double  a[6], v, f;

    data[2] = bswap_32(in[2]);
    data[1] = bswap_32(in[1]);
    data[0] = bswap_32(in[0]);

    /* split input data into 24 bit double values   */
    a[0] =  data[2] & 0x00ffffff;
    a[1] = (data[2] >> 24) | ((data[1] & 0x0000ffff) << 8);
    a[2] = (data[1] >> 16) | ((data[0] & 0x000000ff) << 16);
    a[3] =  data[0] >> 8;

    /* add into the running hash value              */
    a[0] += ctx->hash[0]; a[1] += ctx->hash[1];
    a[2] += ctx->hash[2]; a[3] += ctx->hash[3];
    a[4] = ctx->hash[4]; a[5] = ctx->hash[5];

    /* calculate the low five terms of the product  */
    ctx->hash[0] = a[0] * ctx->zval[0];
    ctx->hash[1] = a[1] * ctx->zval[0]
                 + a[0] * ctx->zval[1];
    ctx->hash[2] = a[2] * ctx->zval[0]
                 + a[1] * ctx->zval[1]
                 + a[0] * ctx->zval[2];
    ctx->hash[3] = a[3] * ctx->zval[0]
                 + a[2] * ctx->zval[1]
                 + a[1] * ctx->zval[2]
                 + a[0] * ctx->zval[3];
    ctx->hash[4] = a[4] * ctx->zval[0]
                 + a[3] * ctx->zval[1]
                 + a[2] * ctx->zval[2]
                 + a[1] * ctx->zval[3]
                 + a[0] * ctx->zval[4];
    ctx->hash[5] = a[5] * ctx->zval[0]
                 + a[4] * ctx->zval[1]
                 + a[3] * ctx->zval[2]
                 + a[2] * ctx->zval[3]
                 + a[1] * ctx->zval[4]
                 + a[0] * ctx->zval[5];

    v = a[5] * ctx->zval[5];    /* add in r[10] term */
    f = (v + tp59) - tp59;
    ctx->hash[4] += tp17 * (v - f);
    ctx->hash[5] += tm07 * f;

    /* do a modular reduction step  */
    f = (ctx->hash[5] + tp59) - tp59;
    ctx->hash[5] -= f;
    ctx->hash[0] += tm07 * f;

    v = a[5] * ctx->zval[1]
      + a[4] * ctx->zval[2]
      + a[3] * ctx->zval[3]
      + a[2] * ctx->zval[4]
      + a[1] * ctx->zval[5];    /* add in r[6] term  */
    f = (v + tp59) - tp59;
    ctx->hash[0] += tp17 * (v - f);
    ctx->hash[1] += tm07 * f;

    v = a[5] * ctx->zval[2]
      + a[4] * ctx->zval[3]
      + a[3] * ctx->zval[4]
      + a[2] * ctx->zval[5];    /* add in r[7] term  */
    f = (v + tp59) - tp59;
    ctx->hash[1] += tp17 * (v - f);
    ctx->hash[2] += tm07 * f;

    v = a[5] * ctx->zval[3]
      + a[4] * ctx->zval[4]
      + a[3] * ctx->zval[5];    /* add in r[8] term  */
    f = (v + tp59) - tp59;
    ctx->hash[2] += tp17 * (v - f);
    ctx->hash[3] += tm07 * f;

    v = a[5] * ctx->zval[4]
      + a[4] * ctx->zval[5];    /* add in r[9] term  */
    f = (v + tp59) - tp59;
    ctx->hash[3] += tp17 * (v - f);
    ctx->hash[4] += tm07 * f;

    /* ripple the carries           */
    f = (ctx->hash[0] + tp76) - tp76;
    ctx->hash[0] -= f;
    ctx->hash[1] += tm24 * f;

    f = (ctx->hash[1] + tp76) - tp76;
    ctx->hash[1] -= f;
    ctx->hash[2] += tm24 * f;

    f = (ctx->hash[2] + tp76) - tp76;
    ctx->hash[2] -= f;
    ctx->hash[3] += tm24 * f;

    f = (ctx->hash[3] + tp76) - tp76;
    ctx->hash[3] -= f;
    ctx->hash[4] += tm24 * f;

    f = (ctx->hash[4] + tp76) - tp76;
    ctx->hash[4] -= f;
    ctx->hash[5] += tm24 * f;

    /* do a modular reduction step  */
    f = (ctx->hash[5] + tp59) - tp59;
    ctx->hash[5] -= f;
    ctx->hash[0] += tm07 * f;
}

#endif

#else

/* add multiple length unsigned values in big endian form   */
/* little endian long words in big endian word order        */

void add_4(unsigned long l[], unsigned long r[])
{   unsigned long   ss, cc;

    ss = l[3] + r[3];
    cc = (ss < l[3] ? 1 : 0);
    l[3] = ss;

    ss = l[2] + r[2] + cc;
    cc = (ss < l[2] ? 1 : ss > l[2] ? 0 : cc);
    l[2] = ss;

    ss = l[1] + r[1] + cc;
    cc = (ss < l[1] ? 1 : ss > l[1] ? 0 : cc);
    l[1] = ss;

    l[0] += r[0] + cc;
}

/* multiply multiple length unsigned values in big endian form  */
/* little endian long words in big endian word order            */

void mlt_4(unsigned long r[], const unsigned long a[], const unsigned long b[])
{   unsigned long long  ch, cl, sm;
    int     i, j, k;

    for(i = 0, cl = 0; i < 8; ++i)
    {
        /* number of terms in sum   */
        k = (i < 3 ? 0 : i - 3);

        for(j = k, ch = 0; j <= i - k; ++j)
        {
            sm = (unsigned long long)a[3 - j] * b[3 - i + j];
            cl += (unsigned long)sm;
            ch += (sm >> 32);
        }

        r[7 - i] = (unsigned long)cl;
        cl = (cl >> 32) + ch;
    }
}

/* Carter-Wegman hash iteration on 12 bytes of data */

void do_cwc(unsigned long in[], mode(ctx) ctx[1])
{   unsigned long   *pt = ctx->hash + (mode(CBLK_SIZE) >> 2), data[4];

    /* put big endian 32-bit items into little endian order     */
    data[3] = bswap_32(in[2]);
    data[2] = bswap_32(in[1]);
    data[1] = bswap_32(in[0]);
    data[0] = 0;

    /* add current hash value into the current data block   */
    add_4(data, ctx->hash);

    /* multiply by the hash key in Z                        */
    mlt_4(ctx->hash, data, ctx->zval);

    /* we now want to find the remainder when divided by    */
    /* (2^127 - 1).  If hash = 2^128 * hi + lo, we can see  */
    /* that hash = (2^127 - 1) * 2 * hi + 2 * hi + lo, so   */
    /* we can set the 128 bit remainder as 2 * hi + lo      */

    add_4(ctx->hash, ctx->hash);/* 2 * hi - if top bit = 1  */
    if(*pt & 0x80000000)    /* another 2^127-1 has to be    */
    {                       /* subtracted from the result   */
        *pt &= 0x7fffffff;
        *(pt - 1) += 1;
    }

    add_4(ctx->hash, pt);       /* 2 * hi + lo - adjust the */
    if(*ctx->hash & 0x80000000) /* result again (as above)  */
    {
        *ctx->hash &= 0x7fffffff;
        be_inc((unsigned long*)ctx->hash, 0);
    }
}

#endif

ret_type mode(init_and_key)(            /* initialise mode and set key          */
            const unsigned char key[],          /* the key value                */
            unsigned long key_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    unsigned long   zv[mode(CBLK_SIZE) >> 2];

    if(key_len != 16 && key_len != 24 && key_len != 32)
        return FAILURE;

    /* set all bytes in the context to zero     */
    memset(ctx, 0, sizeof(mode(ctx)));

    /* set up encryption context                */
    aes_encrypt_key(key, key_len, ctx->enc_ctx);

    /* initialise cwc z value                   */
    memset(zv, 0, (mode(CBLK_SIZE) >> 2) * sizeof(unsigned long));
    ((unsigned char*)zv)[0] = 0xc0;
    aes_encrypt((unsigned char*)zv, (unsigned char*)zv, ctx->enc_ctx);
    ((unsigned char*)zv)[0] &= 0x7f;
    bsw_32(zv, 4);

#if defined( USE_FLOATS )
    /* set FPU to operate in 53 bit precision   */
    /* and in truncate to zero mode             */
    set_FPU;

    /* set up the z value in 24 bit doubles     */
    ctx->zval[0] =  zv[3] & 0x00ffffff;
    ctx->zval[1] = (zv[3] >> 24) | ((zv[2] & 0x0000ffff) << 8);
    ctx->zval[2] = (zv[2] >> 16) | ((zv[1] & 0x000000ff) << 16);
    ctx->zval[3] =  zv[1] >> 8;
    ctx->zval[4] =  zv[0] & 0x00ffffff;
    ctx->zval[5] =  zv[0] >> 24;
#endif

#if defined(USE_LONGS )
    memcpy(ctx->zval, zv, mode(CBLK_SIZE));
#endif

    return SUCCESS;
}

ret_type mode(init_message)(            /* initialise for a message operation   */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned int i;

    /* set up the initial iv in the context  */
    ctx->ctr_val[0] = 0x80;
    for(i = 0; i < 11; ++i)
        ctx->ctr_val[i + 1] = iv[i];

    ctx->ctr_val[12] = 0; ctx->ctr_val[13] = 0;
    ctx->ctr_val[14] = 0; ctx->ctr_val[15] = 1;
    aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->enc_ctx);
    memset(ctx->cwc_buf, 0, sizeof(ctx->cwc_buf));
    ctx->hdr_cnt = 0;
    ctx->txt_acnt = 0;
    ctx->txt_ccnt = 0;

#if defined( USE_FLOATS )
    ctx->hash[0] = 0; ctx->hash[1] = 0;
    ctx->hash[2] = 0; ctx->hash[3] = 0;
    ctx->hash[4] = 0; ctx->hash[5] = 0;
#endif

#if defined( USE_LONGS )
    memset(ctx->hash, 0, sizeof(ctx->hash));
#endif

    return SUCCESS;
}

ret_type mode(auth_header)(             /* authenticate the message header      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = ctx->hdr_cnt;

    if(!hdr_len) return SUCCESS;

	b_pos -= (b_pos / ABLK_LEN) * ABLK_LEN;

	if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < hdr_len)
            lp08(ctx->cwc_buf)[b_pos++] = hdr[cnt++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((hdr + cnt - lp08(ctx->cwc_buf)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            {
				*lp(lp08(ctx->cwc_buf) + b_pos) = *lp(hdr + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= hdr_len)
            {
	            do_cwc(ctx->cwc_buf, ctx);
				memcpy(ctx->cwc_buf, hdr + cnt, ABLK_LEN);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
	else
	{
		while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
			lp08(ctx->cwc_buf)[b_pos++] = hdr[cnt++];

		while(cnt + ABLK_LEN <= hdr_len)
		{
			do_cwc(ctx->cwc_buf, ctx);
			memcpy(ctx->cwc_buf, hdr + cnt, ABLK_LEN);
			cnt += ABLK_LEN;
			b_pos = ABLK_LEN;
		}
	}

	while(cnt < hdr_len)
    {
        if(b_pos == ABLK_LEN)
        {
	        do_cwc(ctx->cwc_buf, ctx);
            b_pos = 0;
        }
        lp08(ctx->cwc_buf)[b_pos++] = hdr[cnt++];
    }

    if(b_pos) /* if bytes remain in the buffer    */
    {
        while(b_pos < ABLK_LEN)
            ((unsigned char*)ctx->cwc_buf)[b_pos++] = 0;

        do_cwc(ctx->cwc_buf, ctx);
    }

    ctx->hdr_cnt += hdr_len;
    return SUCCESS;
}

ret_type mode(auth_data)(               /* authenticate ciphertext data         */
            const unsigned char data[],         /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = ctx->txt_acnt;

    if(!data_len) return SUCCESS;

	b_pos -= (b_pos / ABLK_LEN) * ABLK_LEN;

	if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < data_len)
            lp08(ctx->cwc_buf)[b_pos++] = data[cnt++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((data + cnt - lp08(ctx->cwc_buf)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= data_len && b_pos < ABLK_LEN)
            {
				*lp(lp08(ctx->cwc_buf) + b_pos) = *lp(data + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= data_len)
            {
	            do_cwc(ctx->cwc_buf, ctx);
				memcpy(ctx->cwc_buf, data + cnt, ABLK_LEN);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
	else
	{	
		while(cnt + ABLK_LEN <= data_len && b_pos < ABLK_LEN)
			lp08(ctx->cwc_buf)[b_pos++] = data[cnt++];

		while(cnt + ABLK_LEN <= data_len)
		{
			do_cwc(ctx->cwc_buf, ctx);
			memcpy(ctx->cwc_buf, data + cnt, ABLK_LEN);
			cnt += ABLK_LEN;
			b_pos = ABLK_LEN;
		}
	}

	while(cnt < data_len)
    {
        if(b_pos == ABLK_LEN)
        {
	        do_cwc(ctx->cwc_buf, ctx);
            b_pos = 0;
        }
        lp08(ctx->cwc_buf)[b_pos++] = data[cnt++];
    }

    if(b_pos == ABLK_LEN)
        do_cwc(ctx->cwc_buf, ctx);

    ctx->txt_acnt += data_len;
    return SUCCESS;
}

ret_type mode(crypt_data)(              /* decrypt ciphertext data              */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = ctx->txt_ccnt;

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
	            be_inc(ctx->ctr_val, 12);
		        aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->enc_ctx);
                xor_block_aligned(data + cnt, ctx->enc_ctr);
                cnt += CBLK_LEN;
                b_pos = 0;
            }
        }
    }
	else
	{
		while(cnt + CBLK_LEN <= data_len && b_pos < CBLK_LEN)
			data[cnt++] ^= lp08(ctx->enc_ctr)[b_pos++];

		while(cnt + CBLK_LEN <= data_len)
		{
			be_inc(ctx->ctr_val, 12);
			aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->enc_ctx);
			xor_block(data + cnt, ctx->enc_ctr);
			cnt += CBLK_LEN;
			b_pos = 0;
		}
	}

    while(cnt < data_len)
    {
        if(b_pos == CBLK_LEN)
        {
            be_inc(ctx->ctr_val, 12);
            aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->enc_ctx);
            b_pos = 0;
        }
        data[cnt++] ^= ctx->enc_ctr[b_pos++];
    }

    ctx->txt_ccnt += data_len;
    return SUCCESS;
}

ret_type mode(compute_tag)(             /* compute message authentication tag   */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned int    pos;
    unsigned long   hh[4];

    pos = ctx->txt_acnt;
    pos -= (pos / ABLK_LEN) * ABLK_LEN;
    if(pos)
    {
        while(pos < ABLK_LEN)
            ((unsigned char*)ctx->cwc_buf)[pos++] = 0;

        do_cwc(ctx->cwc_buf, ctx);
    }

#if defined( USE_FLOATS )

/*  For 64-bit data lengths:

    ctx->hash[0] += (ctx->txt_ccnt & 0xffffffff);
    ctx->hash[1] += 256.0 * (ctx->txt_ccnt >> 32);
    ctx->hash[2] += 65536.0 * (ctx->hdr_cnt & 0xffffffff);
    ctx->hash[4] += (ctx->hdr_cnt >> 32);
*/
    ctx->hash[0] += ctx->txt_ccnt;
    ctx->hash[2] += 65536.0 * ctx->hdr_cnt;

    freeze(ctx->hash, 1);

    hh[0] =   ((unsigned long)ctx->hash[4])
          |  (((unsigned long)ctx->hash[5]) << 24);
    hh[1] =  (((unsigned long)ctx->hash[2]) >> 16)
          |  (((unsigned long)ctx->hash[3]) << 8);
    hh[2] =  (((unsigned long)ctx->hash[1]) >>  8)
          | ((((unsigned long)ctx->hash[2]) & 0x0000ffff) << 16);
    hh[3] =   ((unsigned long)ctx->hash[0])
          |  (((unsigned long)ctx->hash[1]) << 24);
#endif

#if defined( USE_LONGS )

/*  For 64-bit data lengths:

	hh[0] = (ctx->hdr_cnt >> 32);
    hh[1] = (ctx->hdr_cnt & 0xffffffff);
    hh[2] = (ctx->txt_ccnt >> 32);
    hh[3] = (ctx->txt_ccnt & 0xffffffff);
*/
	hh[0] = 0;
    hh[1] = ctx->hdr_cnt;
    hh[2] = 0;
    hh[3] = ctx->txt_ccnt;
    add_4(ctx->hash, hh);

    if(ctx->hash[0] & 0x80000000)
    {
        ctx->hash[0] &= 0x7fffffff;
        be_inc(ctx->hash, 0);
    }

    hh[0] = ctx->hash[0];
    hh[1] = ctx->hash[1];
    hh[2] = ctx->hash[2];
    hh[3] = ctx->hash[3];
#endif

    bsw_32(hh, 4);
    aes_encrypt((unsigned char*)hh, (unsigned char*)hh, ctx->enc_ctx);

    ctx->ctr_val[12] = 0; ctx->ctr_val[13] = 0;
    ctx->ctr_val[14] = 0; ctx->ctr_val[15] = 0;
    aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->enc_ctx);

    for(pos = 0; pos < tag_len; ++pos)
        tag[pos] = ((unsigned char*)hh)[pos] ^ ctx->enc_ctr[pos];
    return SUCCESS;
}

ret_type mode(end)(                     /* clean up and end operation           */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    memset(ctx, 0, sizeof(mode(ctx)));
#if defined( USE_FLOATS )
    reset_FPU;
#endif
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

