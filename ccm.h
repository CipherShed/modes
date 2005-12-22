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

 This code implements the CCM combined encryption and authentication mode
 specified by Doug Whiting, Russ Housley and Niels Ferguson.  Relevant
 documents are:

    NIST Special Publication 800-38C: DRAFT Recommendation for Block Cipher
    Modes of Operation: The CCM Mode For AUthentication and Confidentiality.
    September 2003.

    IEEE Std 802.11i/D5.0, August 2003.   Draft Amendment to standard for
    Telecommunications and Information Exchange Between Systems - LAN/MAN
    Specific Requirements - Part 11: Wireless Medium Access Control (MAC)
    and physical layer (PHY) specifications:  Medium Access Control (MAC)
    Security Enhancements

 The length of the mesaage data must be less than 2^32 bytes unless the
 define LONG_MESSAGES is set.  NOTE that this implementation is not fully
 compliant with the CCM specification because, if an authentication error
 is detected when the last block is processed, blocks processed earlier will
 already have been returned to the caller. This violates the specification
 but is costly to avoid for large messages that cannot be memory resident as
 a single block. In this case the message would have to be processed twice
 so that the final authentication value can be checked before the output is
 provided on a second pass.

 My thanks go to Erik Andersen <andersen@codepoet.org> for finding a bug in
 an earlier relaease of this code. I am also grateful for the comments made
 by James Weatherall <jnw@realvnc.com> that led to several API changes.
*/

#ifndef _CCM_H
#define _CCM_H

#include "aes.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifdef mode
#undef mode
#endif
#define mode(x)         CCM_##x
#define CCM_BLOCK_SIZE  AES_BLOCK_SIZE
#define SUCCESS         0
#define FAILURE         1

/* CCM error codes  */

#define CCM_ok                       0
#define CCM_bad_key                 -1
#define CCM_bad_auth_field_length   -2
#define CCM_bad_auth_data_length    -3
#define CCM_bad_nonce_length        -4
#define CCM_bad_auth_call           -5
#define CCM_auth_length_error       -6
#define CCM_msg_length_error        -7
#define CCM_auth_failure            -8

typedef int  ret_type;

/* The CCM context  */

typedef struct
{   unsigned char   ctr_val[CCM_BLOCK_SIZE];    /* counter block                */
    unsigned char   enc_ctr[CCM_BLOCK_SIZE];    /* encrypted counter block      */
    unsigned char   cbc_buf[CCM_BLOCK_SIZE];    /* running CBC value            */
    aes_encrypt_ctx aes[1];                     /* AES context                  */
    unsigned long   iv_len;                     /* the nonce length             */
    unsigned long   hdr_len;                    /* the associated data length   */
    unsigned long   msg_len;                    /* message data length          */
    unsigned long   tag_len;                    /* authentication field length  */
    unsigned long   hdr_lim;                    /* message auth length (bytes)  */
    unsigned long   cnt;                        /* position counter             */
    unsigned long   txt_acnt;                   /* position counter             */
    ret_type        state;                      /* algorithm state/error value  */
} mode(ctx);

ret_type mode(init_and_key)(            /* initialise mode and set key          */
            const unsigned char key[],          /* the key value                */
            unsigned long key_len,              /* and its length in bytes      */
            mode(ctx) ctx[1]);                  /* the mode context             */

ret_type mode(init_message)(            /* initialise for a message operation   */
            const unsigned char iv[],           /* the initialisation vector    */
            unsigned long iv_len,               /* the nonce length             */
            unsigned long hdr_len,              /* the associated data length   */
            unsigned long msg_len,              /* message data length          */
            unsigned long tag_len,              /* authentication field length  */
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
