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

 This code implements the EAX combined encryption and authentication mode
 specified M. Bellare, P. Rogaway and D. Wagner.

 This is a byte oriented version in which the nonce is of limited length
*/

#include "eax.h"

#define BUFFER_ALIGN32
#define IN_LINES

#include "mode_hdr.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define CBLK_LEN   mode(BLOCK_SIZE)     /* encryption block length          */
#define ABLK_LEN   mode(BLOCK_SIZE)     /* authentication block length      */
#define CBLK_MASK  (CBLK_LEN - 1)       /* mask for encryption position     */
#define ABLK_MASK  (ABLK_LEN - 1)       /* mask for authentication position */

#define inc_ctr(x)  \
    {   int i = CBLK_LEN; while(i-- > 0 && !++(lp08(x)[i])) ; }

ret_type mode(init_and_key)(            /* initialise mode and set key          */
            const unsigned char key[],          /* the key value                */
            unsigned long key_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   static unsigned char x_t[4] = { 0x00, 0x87, 0x0e, 0x87 ^ 0x0e };
    unsigned char t, *p;
    unsigned int i;

    /* set the context to all zeroes            */
    memset(ctx, 0, sizeof(mode(ctx)));

    /* set the AES key                          */
    aes_encrypt_key(key, key_len, ctx->aes);

    /* compute E(0) (needed for the pad values) */
    aes_encrypt(ctx->pad_xvv, ctx->pad_xvv, ctx->aes);

    /* compute {02} * {E(0)} and {04} * {E(0)}  */
    /* GF(2^128) mod x^128 + x^7 + x^2 + x + 1  */
    for(i = 0, p = ctx->pad_xvv, t = *p >> 6; i < mode(BLOCK_SIZE) - 1; ++i, ++p)
    {
        *(p + 16) = (*p << 2) | (*(p + 1) >> 6);
        *p = (*p << 1) | (*(p + 1) >> 7);
    }
    *(p + 16) = (*p << 2) ^ x_t[t];
    *(p + 15) ^= (t >>= 1);
    *p = (*p << 1) ^ x_t[t];

    return SUCCESS;
}

ret_type mode(init_message)(            /* initialise for a message operation   */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned int i = 0, n_pos = 0;
    unsigned char *p;

    memset(ctx->nce_cbc, 0, mode(BLOCK_SIZE));
    memset(ctx->hdr_cbc, 0, mode(BLOCK_SIZE));
    memset(ctx->txt_cbc, 0, mode(BLOCK_SIZE));

    /* set the header CBC start value           */
    ctx->hdr_cbc[mode(BLOCK_SIZE) - 1] = 1;
    ctx->hdr_cnt = 16;

    /* set the ciphertext CBC start value       */
    ctx->txt_cbc[mode(BLOCK_SIZE) - 1] = 2;
    ctx->txt_ccnt = 16; /* encryption count     */
    ctx->txt_acnt = 16; /* authentication count */

    /* if the nonce length is zero, the OMAC    */
    /* message is a block of zeroes which gives	*/
	/* the pre-encrypted tag as the Lu value	*/
    if(iv_len)
	{
        n_pos = 16;

		/* compile the OMAC value for the nonce     */
		i = 0;
		while(i < iv_len)
		{
			if(n_pos == mode(BLOCK_SIZE))
			{
				aes_encrypt(ctx->nce_cbc, ctx->nce_cbc, ctx->aes);
				n_pos = 0;
			}
			ctx->nce_cbc[n_pos++] ^= iv[i++];
		}

		/* do the OMAC padding for the nonce        */
		p = ctx->pad_xvv;
		if(n_pos < mode(BLOCK_SIZE))
		{
			ctx->nce_cbc[n_pos] ^= 0x80; p += 16;
		}

		for(i = 0; i < mode(BLOCK_SIZE); ++i)
			ctx->nce_cbc[i] ^= p[i];
	}
	else
		memcpy(ctx->nce_cbc, ctx->pad_xvv, mode(BLOCK_SIZE));

    /* compute the OMAC*(nonce) value           */
    aes_encrypt(ctx->nce_cbc, ctx->nce_cbc, ctx->aes);

    /* copy value into counter for CTR          */
    memcpy(ctx->ctr_val, ctx->nce_cbc, mode(BLOCK_SIZE));
    return SUCCESS;
}

ret_type mode(auth_header)(             /* authenticate the message header      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = ctx->hdr_cnt;

    if(!hdr_len) return SUCCESS;

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < hdr_len)
            lp08(ctx->hdr_cbc)[b_pos++] ^= hdr[cnt++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((hdr + cnt - lp08(ctx->hdr_cbc)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            {
                 *lp(lp08(ctx->hdr_cbc) + b_pos) ^= *lp(hdr + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= hdr_len)
            {
                aes_encrypt(ctx->hdr_cbc, ctx->hdr_cbc, ctx->aes);
	            xor_block_aligned(ctx->hdr_cbc, hdr + cnt);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            lp08(ctx->hdr_cbc)[b_pos++] ^= hdr[cnt++];

        while(cnt + ABLK_LEN <= hdr_len)
        {
            aes_encrypt(ctx->hdr_cbc, ctx->hdr_cbc, ctx->aes);
            xor_block(ctx->hdr_cbc, hdr + cnt);
            cnt += ABLK_LEN;
            b_pos = ABLK_LEN;
        }
    }

    while(cnt < hdr_len)
    {
        if(b_pos == ABLK_LEN)
        {
            aes_encrypt(ctx->hdr_cbc, ctx->hdr_cbc, ctx->aes);
            b_pos = 0;
        }
        lp08(ctx->hdr_cbc)[b_pos++] ^= hdr[cnt++];
    }

    ctx->hdr_cnt = b_pos;
    return SUCCESS;
}

ret_type mode(auth_data)(               /* authenticate ciphertext data         */
            const unsigned char data[],         /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = ctx->txt_acnt;

    if(!data_len) return SUCCESS;

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        while((b_pos & ADR_MASK) && cnt < data_len)
            lp08(ctx->txt_cbc)[b_pos++] ^= data[cnt++];

        /* if cnt is a multiple of four, see if the input buffer    */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((data + cnt - lp08(ctx->txt_cbc)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */

            while(cnt + CBLK_LEN <= data_len && b_pos < CBLK_LEN)
            {
                *lp(lp08(ctx->txt_cbc) + b_pos) ^= *lp(data + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + CBLK_LEN <= data_len)
            {
                aes_encrypt(ctx->txt_cbc, ctx->txt_cbc, ctx->aes);
                xor_block_aligned(ctx->txt_cbc, data + cnt);
                cnt += CBLK_LEN;
                b_pos = CBLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + CBLK_LEN <= data_len && b_pos < CBLK_LEN)
            lp08(ctx->txt_cbc)[b_pos++] ^= data[cnt++];

        while(cnt + CBLK_LEN <= data_len)
        {
            aes_encrypt(ctx->txt_cbc, ctx->txt_cbc, ctx->aes);
            xor_block(ctx->txt_cbc, data + cnt);
            cnt += CBLK_LEN;
            b_pos = CBLK_LEN;
        }
    }

    while(cnt < data_len)
    {
        if(b_pos == mode(BLOCK_SIZE))
        {
            aes_encrypt(ctx->txt_cbc, ctx->txt_cbc, ctx->aes);
            b_pos = 0;
        }
        lp08(ctx->txt_cbc)[b_pos++] ^= data[cnt++];
    }

    ctx->txt_acnt = b_pos;
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
                aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
                inc_ctr(ctx->ctr_val);
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
            aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
            inc_ctr(ctx->ctr_val);
            xor_block(data + cnt, ctx->enc_ctr);
            cnt += CBLK_LEN;
            b_pos = CBLK_LEN;
        }
    }

    while(cnt < data_len)
    {
        if(b_pos == mode(BLOCK_SIZE))
        {
            aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
            inc_ctr(ctx->ctr_val);
            b_pos = 0;
        }
        data[cnt++] ^= lp08(ctx->enc_ctr)[b_pos++];
    }

    ctx->txt_ccnt = b_pos;
    return SUCCESS;
}

ret_type mode(compute_tag)(             /* compute message authentication tag   */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned int i;
    unsigned char   *p;

    /* complete OMAC* for header value      */
    p = ctx->pad_xvv;
    if(ctx->hdr_cnt < ABLK_LEN)
    {
        lp08(ctx->hdr_cbc)[ctx->hdr_cnt] ^= 0x80;
        p += 16;
    }

    for(i = 0; i < mode(BLOCK_SIZE); ++i)
        lp08(ctx->hdr_cbc)[i] ^= p[i];

    aes_encrypt(ctx->hdr_cbc, ctx->hdr_cbc, ctx->aes);

    /* complete OMAC* for ciphertext value  */
    p = ctx->pad_xvv;
    if(ctx->txt_acnt < ABLK_LEN)
    {
        lp08(ctx->txt_cbc)[ctx->txt_acnt] ^= 0x80;
        p += 16;
    }

    for(i = 0; i < mode(BLOCK_SIZE); ++i)
        lp08(ctx->txt_cbc)[i] ^= p[i];

    aes_encrypt(ctx->txt_cbc, ctx->txt_cbc, ctx->aes);

    /* compute final authentication tag     */
    for(i = 0; i < (unsigned int)tag_len; ++i)
        tag[i] = ctx->nce_cbc[i] ^ ctx->txt_cbc[i] ^ ctx->hdr_cbc[i];
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
