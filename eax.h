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
*/

#ifndef _EAX_H
#define _EAX_H

#include "aes.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifdef mode
#undef mode
#endif
#define mode(x)			EAX_##x
#define EAX_BLOCK_SIZE  AES_BLOCK_SIZE
#define SUCCESS         0
#define FAILURE         1

/* The EAX-AES  context  */

typedef struct
{
    unsigned char   ctr_val[AES_BLOCK_SIZE];    /* CTR counter value            */
    unsigned char   enc_ctr[AES_BLOCK_SIZE];    /* encrypted CTR block          */
    unsigned char   hdr_cbc[AES_BLOCK_SIZE];    /* encrypt(1), for header CBC   */
    unsigned char   txt_cbc[AES_BLOCK_SIZE];    /* encrypt(2), for ctext CBC    */
    unsigned char   nce_cbc[AES_BLOCK_SIZE];    /* encrypt (0|nonce), for iv CBC*/
    unsigned char   pad_xvv[2*AES_BLOCK_SIZE];  /* {02} encrypt(0), pad values  */
    aes_encrypt_ctx aes[1];                     /* AES encryption context       */
    unsigned long   hdr_cnt;                    /* header bytes so far          */
    unsigned long   txt_ccnt;                   /* text bytes so far (encrypt)  */
    unsigned long   txt_acnt;                   /* text bytes so far (auth)     */
} mode(ctx);

typedef int  ret_type;

ret_type mode(init_and_key)(            /* initialise mode and set key          */
            const unsigned char key[],          /* the key value                */
            unsigned long key_len,              /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(init_message)(            /* initialise for a message operation   */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(auth_header)(             /* authenticate the message header      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(auth_data)(               /* authenticate ciphertext data         */
            const unsigned char data[],         /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(crypt_data)(              /* decrypt ciphertext data              */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(compute_tag)(             /* compute message authentication tag   */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(end)(                     /* clean up and end operation           */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(encrypt)(                 /* encrypt and authenticate data        */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(decrypt)(                 /* authenticate and decrypt data        */
            unsigned char data[],               /* the data buffer              */
            unsigned long data_len,             /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(encrypt_message)(         /* encrypt an entire message            */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            unsigned char msg[],                /* the message buffer           */
            unsigned long msg_len,              /* and its length in bytes      */
            unsigned char tag[],                /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(decrypt_message)(         /* decrypt an entire message            */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* and its length in bytes      */
            const unsigned char hdr[],          /* the header buffer            */
            unsigned long hdr_len,              /* and its length in bytes      */
            unsigned char msg[],                /* the message buffer           */
            unsigned long msg_len,              /* and its length in bytes      */
            const unsigned char tag[],          /* the buffer for the tag       */
            unsigned long tag_len,              /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

#if defined(__cplusplus)
}
#endif

#endif
