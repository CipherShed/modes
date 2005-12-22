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
 Issue Date: 9/09/2003
*/

#include <memory.h>

#include "ccm.h"

#define BUFFER_ALIGN32
//#define IN_LINES

#include "mode_hdr.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define LONG_MESSAGES

#define CBLK_LEN   mode(BLOCK_SIZE) /* encryption block length          */
#define ABLK_LEN   mode(BLOCK_SIZE) /* authentication block length      */
#define CBLK_MASK  (CBLK_LEN - 1)   /* mask for encryption position     */
#define ABLK_MASK  (ABLK_LEN - 1)   /* mask for authentication position */

#define init_state 1
#define auth_state 2
#define msg_state  3

/* These values are used to detect long word alignment in order */
/* to speed up some CCM buffer operations. This facility may    */
/* need to be disabled (by setting A_PWR to 0) on some machines */

#define A_PWR   2

#define A_SIZE      (1 << A_PWR)
#define A_MASK      (A_SIZE - 1)

#define ctr_len(x)  (((*(unsigned char*)(x)) & 0x07) + 1)

#define clr_ctr(x,l)   memset((x) + CBLK_LEN - (l), 0, (l))

#define set_ctr(x,v)                                        \
    {   unsigned char *_p = (unsigned char*)(x) + CBLK_LEN; \
        unsigned long _t = (v), _l = ctr_len(x);            \
        do													\
        {    *--_p = (unsigned char)_t; _t >>= 8; }         \
		while(--_l);										\
    }

#define inc_ctr(x)                                          \
    {   unsigned char *_p = (unsigned char*)(x) + CBLK_LEN; \
        unsigned long _l = ctr_len(x);                      \
        while(_l-- && ++(*--_p) == 0) ;                     \
    }

#ifdef LONG_MESSAGES
#define mlen_len(x)                     \
    (((x) & 0xff00000000000000) ? 7 :   \
     ((x) & 0xffff000000000000) ? 6 :   \
     ((x) & 0xffffff0000000000) ? 5 :   \
     ((x) & 0xffffffff00000000) ? 4 :   \
     ((x) & 0xffffffffff000000) ? 3 :   \
     ((x) & 0xffffffffffff0000) ? 2 : 1)
#else
#define mlen_len(x) (((x) & 0xff000000) ? 3 : ((x) & 0xffff0000) ? 2 : 1)
#endif

ret_type mode(init_and_key)(            /* initialise mode and set key          */
            const unsigned char key[],          /* the key value                */
            unsigned long key_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    ctx->state = CCM_ok;
    if(key_len != 16 && key_len != 24 && key_len != 32)
        ctx->state = CCM_bad_key;
    aes_encrypt_key(key, key_len, ctx->aes);
    return SUCCESS;
}

ret_type mode(init_message)(            /* initialise for a message operation   */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* the nonce length             */
            unsigned long hdr_len,              /* the associated data length   */
            unsigned long msg_len,              /* message data length          */
            unsigned long tag_len,              /* authentication field length  */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned int cnt;

    ctx->state = CCM_ok;

    if(tag_len < 2 || tag_len > 16 || (tag_len & 1))
        ctx->state = CCM_bad_auth_field_length;
    else if(iv_len && iv_len < 7 || iv_len > 13)
        ctx->state = CCM_bad_nonce_length;
    if(ctx->state)
        return ctx->state;

    ctx->iv_len = iv_len;
    ctx->hdr_len = hdr_len;
    ctx->msg_len = msg_len;
    ctx->tag_len = tag_len;
    ctx->cnt = 0;
    ctx->txt_acnt = 0;
    ctx->hdr_lim = hdr_len;

    ctx->ctr_val[0] = 
		(unsigned char)(iv_len ? CBLK_LEN - 2 - iv_len : mlen_len(ctx->msg_len));

    /* move the iv into the block    */
    for(cnt = 1; cnt < (aes_32t)CBLK_LEN - ctx->ctr_val[0] - 1; ++cnt)
        ctx->ctr_val[cnt] = iv[cnt - 1];

    clr_ctr(ctx->ctr_val, ctx->ctr_val[0] + 1);         /* clear the counter value  */
    memcpy(ctx->cbc_buf, ctx->ctr_val, CBLK_LEN);       /* copy block to CBC buffer */
    ctx->ctr_val[CBLK_LEN - 1] = 1;						/* set initial counter      */
    set_ctr(ctx->cbc_buf, ctx->msg_len);				/* store the message length */

    ctx->cbc_buf[0] |= (ctx->hdr_lim ? 0x40 : 0) + ((ctx->tag_len - 2) << 2);

    aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);  /* encrypt the cbc block    */
    aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);  /* encrypt counter block    */

    if(ctx->hdr_len)
    {       /* encode the length field if there is some associated data */

        if(ctx->hdr_len < 65536 - 256)
        {
            ctx->cbc_buf[0] ^= (unsigned char)(ctx->hdr_lim >> 8);
            ctx->cbc_buf[1] ^= (unsigned char) ctx->hdr_lim;
            ctx->cnt = 2;
        }
#ifndef LONG_MESSAGES
        else
        {
            ctx->state = CCM_auth_length_error;
            return ctx->state;
        }
#else
        else if(ctx->hdr_len < 0x0000000100000000)
        {
            ctx->cbc_buf[0] ^= 0xff;
            ctx->cbc_buf[1] ^= 0xfe;
            ctx->cbc_buf[2] ^= (unsigned char)(ctx->hdr_lim >> 24);
            ctx->cbc_buf[3] ^= (unsigned char)(ctx->hdr_lim >> 16);
            ctx->cbc_buf[4] ^= (unsigned char)(ctx->hdr_lim >>  8);
            ctx->cbc_buf[5] ^= (unsigned char) ctx->hdr_lim;
            ctx->cnt = 6;
        }
        else
        {
            ctx->cbc_buf[0] ^= 0xff;
            ctx->cbc_buf[1] ^= 0xff;
            ctx->cbc_buf[2] ^= (unsigned char)(ctx->hdr_lim >> 56);
            ctx->cbc_buf[3] ^= (unsigned char)(ctx->hdr_lim >> 48);
            ctx->cbc_buf[4] ^= (unsigned char)(ctx->hdr_lim >> 40);
            ctx->cbc_buf[5] ^= (unsigned char)(ctx->hdr_lim >> 32);
            ctx->cbc_buf[6] ^= (unsigned char)(ctx->hdr_lim >> 24);
            ctx->cbc_buf[7] ^= (unsigned char)(ctx->hdr_lim >> 16);
            ctx->cbc_buf[8] ^= (unsigned char)(ctx->hdr_lim >>  8);
            ctx->cbc_buf[9] ^= (unsigned char) ctx->hdr_lim;
            ctx->cnt = 10;
        }
#endif
        ctx->hdr_lim += ctx->cnt;
        ctx->state = auth_state;
    }
    else    /* there is no associated data  */
    {
        ctx->cnt = 0;
        ctx->state = msg_state;
    }

    ctx->hdr_lim = ctx->hdr_len + ctx->cnt;
    ctx->txt_acnt = ctx->cnt;

    return CCM_ok;
}

ret_type mode(auth_header)(             /* authenticate the message header      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0, b_pos = (ctx->cnt & ABLK_MASK);

    if(!hdr_len)
        return SUCCESS;

    if(ctx->state < 0)
        return ctx->state;

    if(ctx->state != auth_state)
        return (ctx->state = CCM_bad_auth_call);

    if(ctx->cnt + hdr_len > ctx->hdr_lim)
        return (ctx->state = CCM_auth_length_error);

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position b_pos to be a multiple of four as well   */
        while((b_pos & A_MASK) && cnt < hdr_len)
            lp08(ctx->cbc_buf)[b_pos++] ^= hdr[cnt++];

        /* if b_pos is a multiple of four, see if the input buffer  */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((hdr + cnt - lp08(ctx->ctr_val)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            {
                *lp(lp08(ctx->cbc_buf) + b_pos) ^= *lp(hdr + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= hdr_len)
            {
                aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
                xor_block_aligned(ctx->cbc_buf, hdr + cnt);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + ABLK_LEN <= hdr_len && b_pos < ABLK_LEN)
            lp08(ctx->cbc_buf)[b_pos++] ^= hdr[cnt++];

        while(cnt + ABLK_LEN <= hdr_len)
        {
            aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
            xor_block(ctx->cbc_buf, hdr + cnt);
            cnt += ABLK_LEN;
            b_pos = ABLK_LEN;
        }
    }

    if(b_pos == ABLK_LEN)
    {
        aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
        b_pos = 0;
    }

    while(cnt < hdr_len)
    {
        lp08(ctx->cbc_buf)[b_pos++] ^= hdr[cnt++];

        if(b_pos == ABLK_LEN || ctx->cnt + cnt == ctx->hdr_lim)
        {
            aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
            b_pos = 0;
        }
    }

    if((ctx->cnt += cnt) == ctx->hdr_lim)
    {
        ctx->state = msg_state;
        ctx->cnt = 0;
        ctx->txt_acnt = 0;
    }

    return SUCCESS;
}

ret_type mode(auth_data)(               /* authenticate ciphertext data         */
            const unsigned char data[],         /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long   cnt = 0, b_pos = (ctx->txt_acnt & CBLK_MASK);

    if(ctx->state < 0)
        return ctx->state;

    if(ctx->state == auth_state)
        return (ctx->state = CCM_auth_length_error);

    if(ctx->txt_acnt + data_len > ctx->msg_len)
        return (ctx->state = CCM_msg_length_error);

    if(aligned(ctx))
    {
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position (cnt) to be a multiple of four as well   */
        /* the context (ctx) is 4 byte aligned so we now need the   */
        /* buffer position b_pos to be a multiple of four as well   */
        while((b_pos & A_MASK) && cnt < data_len)
            lp08(ctx->cbc_buf)[b_pos++] ^= data[cnt++];

        /* if b_pos is a multiple of four, see if the input buffer  */
        /* is also on a 4 byte boundary                             */
        if(!(b_pos & ADR_MASK) && !((data + cnt - lp08(ctx->ctr_val)) & ADR_MASK))
        {
            /* process a part filled buffer by filling it if enough */
            /* bytes are available to do this                       */
            while(cnt + ABLK_LEN <= data_len && b_pos < ABLK_LEN)
            {
                *lp(lp08(ctx->cbc_buf) + b_pos) ^= *lp(data + cnt);
                cnt += lp_inc; b_pos += lp_inc;
            }

            while(cnt + ABLK_LEN <= data_len)
            {
                aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
                xor_block_aligned(ctx->cbc_buf, data + cnt);
                cnt += ABLK_LEN;
                b_pos = ABLK_LEN;
            }
        }
    }
    else
    {
        while(cnt + ABLK_LEN <= data_len && b_pos < ABLK_LEN)
            lp08(ctx->cbc_buf)[b_pos++] ^= data[cnt++];

        while(cnt + ABLK_LEN <= data_len)
        {
            aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
            xor_block(ctx->cbc_buf, data + cnt);
            cnt += ABLK_LEN;
            b_pos = ABLK_LEN;
        }
    }

    if(b_pos == ABLK_LEN)
    {
        aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
        b_pos = 0;
    }

    while(cnt < data_len)
    {
        lp08(ctx->cbc_buf)[b_pos++] ^= data[cnt++];

        if(b_pos == ABLK_LEN)
        {
            aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
            b_pos = 0;
        }
    }

    ctx->txt_acnt += cnt;
    return SUCCESS;
}

ret_type mode(crypt_data)(              /* decrypt ciphertext data              */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long   cnt = 0, b_pos = (ctx->cnt & CBLK_MASK);

    if(ctx->state < 0)
        return ctx->state;

    if(ctx->state == auth_state)
        return (ctx->state = CCM_auth_length_error);

    if(ctx->cnt + data_len > ctx->msg_len)
        return (ctx->state = CCM_msg_length_error);

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

    ctx->cnt += cnt;
    return SUCCESS;
}

ret_type mode(compute_tag)(             /* compute message authentication tag   */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{   unsigned long cnt = 0;

    if(ctx->state < 0)
        return ctx->state;

    if(   tag_len != ctx->tag_len 
	   || ctx->state == init_state && ctx->hdr_lim 
	   || ctx->state == auth_state)
        return (ctx->state = CCM_auth_length_error);

    if(   ctx->cnt < ctx->msg_len 
	   || ctx->cnt + tag_len > ctx->msg_len + ctx->tag_len)
        return (ctx->state = CCM_msg_length_error);

    /* if at the start of the authentication field  */
    if(tag_len > 0 && ctx->cnt == ctx->msg_len)
    {
        if(ctx->cnt & CBLK_MASK)
            aes_encrypt(ctx->cbc_buf, ctx->cbc_buf, ctx->aes);
        set_ctr(ctx, 0);
        aes_encrypt(ctx->ctr_val, ctx->enc_ctr, ctx->aes);
    }

    while(cnt < tag_len)
    {   unsigned long pos = ctx->cnt++ - ctx->msg_len;

        tag[cnt++] = ctx->cbc_buf[pos] ^ ctx->enc_ctr[pos];
    }

    return (ret_type)CCM_ok;
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

    mode(auth_data)(data, data_len, ctx);
    mode(crypt_data)(data, data_len, ctx);
    return SUCCESS;
}

ret_type mode(decrypt)(                 /* authenticate and decrypt data        */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1])                   /* the mode context             */
{
    mode(crypt_data)(data, data_len, ctx);
    mode(auth_data)(data, data_len, ctx);
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
    mode(init_message)(iv, iv_len, hdr_len, msg_len, tag_len, ctx);
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

    mode(init_message)(iv, iv_len, hdr_len, msg_len, tag_len, ctx);
    mode(auth_header)(hdr, hdr_len, ctx);
    mode(decrypt)(msg, msg_len, ctx);
    mode(compute_tag)(local_tag, tag_len, ctx);
    return memcmp(tag, local_tag, tag_len) ? FAILURE : SUCCESS;
}

#if defined(__cplusplus)
}
#endif
