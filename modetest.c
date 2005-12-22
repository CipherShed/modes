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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "cycles.h"

char*	in_dir  = "testvals/";
char*	out_dir = "outvals/";

typedef int  ret_type;
typedef ret_type t_init_and_key(const unsigned char*, unsigned long, void*);
typedef ret_type t_init_message(const unsigned char*, unsigned long, void*);
typedef ret_type t_auth_header (const unsigned char*, unsigned long, void*);
typedef ret_type t_auth_data   (const unsigned char*, unsigned long, void*);
typedef ret_type t_crypt_data  (unsigned char*, unsigned long, void*);
typedef ret_type t_compute_tag (unsigned char*, unsigned long, void*);
typedef ret_type t_encrypt     (unsigned char*, unsigned long, void*);
typedef ret_type t_decrypt     (unsigned char*, unsigned long, void*);
typedef ret_type t_encrypt_message(
			const unsigned char*, unsigned long,  
            const unsigned char*, unsigned long,
            unsigned char*, unsigned long,
            unsigned char*, unsigned long,
            void*);
typedef ret_type t_decrypt_message(
			const unsigned char*, unsigned long,  
            const unsigned char*, unsigned long,
            unsigned char*, unsigned long,
            unsigned char*, unsigned long,
            void*);
typedef ret_type t_end(void*);

/* special init_message() call for CCM to replace	*/
/* t_init_message below when CCM is being used		*/
typedef ret_type s_init_message(const unsigned char*,
            unsigned long, unsigned long, unsigned long, unsigned long, void*);

typedef struct
{	char				*name;
	t_init_and_key		*init_and_key;
	t_init_message		*init_message;
	t_auth_header		*auth_header;
	t_auth_data			*auth_data;
	t_crypt_data		*crypt_data;
	t_compute_tag		*compute_tag;
	t_encrypt			*encrypt;
	t_decrypt			*decrypt;
	t_encrypt_message	*encrypt_message;
	t_decrypt_message	*decrypt_message;
	t_end				*end;
} mode_fns;

#include "ccm.h"

void mode(functions)(mode_fns f[1])
{
	f->name = "CCM";
    f->init_and_key = mode(init_and_key);
	f->init_message = mode(init_message);
	f->auth_header = mode(auth_header);
	f->auth_data = mode(auth_data);
	f->crypt_data = mode(crypt_data);
	f->compute_tag = mode(compute_tag);
	f->encrypt	= mode(encrypt);
	f->decrypt	= mode(decrypt);
	f->encrypt_message	= mode(encrypt_message);
	f->decrypt_message	= mode(decrypt_message);
	f->end	= mode(end);
}

#include "cwc.h"

void mode(functions)(mode_fns f[1])
{
	f->name = "CWC";
    f->init_and_key = mode(init_and_key);
	f->init_message = mode(init_message);
	f->auth_header = mode(auth_header);
	f->auth_data = mode(auth_data);
	f->crypt_data = mode(crypt_data);
	f->compute_tag = mode(compute_tag);
	f->encrypt	= mode(encrypt);
	f->decrypt	= mode(decrypt);
	f->encrypt_message	= mode(encrypt_message);
	f->decrypt_message	= mode(decrypt_message);
	f->end	= mode(end);
}

#include "eax.h"

void mode(functions)(mode_fns f[1])
{
	f->name = "EAX";
    f->init_and_key = mode(init_and_key);
	f->init_message = mode(init_message);
	f->auth_header = mode(auth_header);
	f->auth_data = mode(auth_data);
	f->crypt_data = mode(crypt_data);
	f->compute_tag = mode(compute_tag);
	f->encrypt	= mode(encrypt);
	f->decrypt	= mode(decrypt);
	f->encrypt_message	= mode(encrypt_message);
	f->decrypt_message	= mode(decrypt_message);
	f->end	= mode(end);
}

#include "gcm.h"

void mode(functions)(mode_fns f[1])
{
	f->name = "GCM";
    f->init_and_key = mode(init_and_key);
	f->init_message = mode(init_message);
	f->auth_header = mode(auth_header);
	f->auth_data = mode(auth_data);
	f->crypt_data = mode(crypt_data);
	f->compute_tag = mode(compute_tag);
	f->encrypt	= mode(encrypt);
	f->decrypt	= mode(decrypt);
	f->encrypt_message	= mode(encrypt_message);
	f->decrypt_message	= mode(decrypt_message);
	f->end	= mode(end);
}

#ifdef mode
#undef mode
#endif

#define BLOCK_SIZE AES_BLOCK_SIZE

enum line_ty { KEY, IV, HDR, PTX, CTX, TAG };

unsigned int hex(char ch)
{
	if(ch >= '0' && ch <= '9')
		return ch - '0';
	else if(ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	else if(ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	else
		return 0;
}

unsigned char hex_in(char *s)
{
	return 16 * hex(s[0]) + hex(s[1]);
}

unsigned int dec_in(char *s)
{	unsigned int n = 0;

	while(*s >= '0' && *s <= '9')
		n = 10 * n + *s++ - '0';
	return n;
}

void gen_test(mode_fns f[1], void* contx)
{	char			tvi_name[64], tvo_name[64], line[80], *lp;
	FILE			*inf = 0, *outf = 0;
	unsigned char	key[32], iv[256], hdr[256], ptx[256], ctx[256], 
					tag[16], buf[256], tbuf[16], *p;
	int				key_len, iv_len, hdr_len, ptx_len, ctx_len, tag_len,
					hdr_rpt, ptx_rpt, rpt_cnt, vec_no, *cnt, *rpt, err, i;
	enum line_ty	line_is;

	strcpy(tvi_name, in_dir);
	strcat(tvi_name, f->name);
	strcat(tvi_name, ".0");

	strcpy(tvo_name, out_dir);
	strcat(tvo_name, f->name);
	strcat(tvo_name, ".0");

	for( ; ; )
	{
		tvi_name[strlen(tvi_name) - 1]++;
		tvo_name[strlen(tvi_name) - 1]++;

		if(!(inf = fopen(tvi_name, "r")))
			break;

		do
		{
			fgets(line, 80, inf);
		}
		while
            (strncmp(line, "MDE ", 4) != 0);

		if(feof(inf))
			break;

		if(strncmp(line + 4, f->name, 3) != 0)
		{
			printf("\nThe test vector file does not match %s", f->name);
			break;
		}

		if(!(outf = fopen(tvo_name, "w")))
			break;
		fprintf(outf, "\nMDE %s", f->name);

		for(err = 0; ; )
		{
			fgets(line, 80, inf);

			if(strlen(line) < 4)
			{
				key_len = iv_len = hdr_len = ptx_len = 
					ctx_len = tag_len = rpt_cnt = 0;
				hdr_rpt = ptx_rpt = 1;
				fprintf(outf, "\n");
				continue;
			}
			
			if(feof(inf))
				break;

			if(strncmp(line, "VEC ", 4) == 0)
			{
				vec_no = dec_in(line + 4);
				fprintf(outf, "\nVEC %04i", vec_no);
				continue;			
			}
			else if(strncmp(line, "RPT ", 4) == 0)
			{
				*rpt = dec_in(line + 4);
				fprintf(outf, "\nRPT %04i", *rpt);
				continue;
			}
			else if(strncmp(line, "KEY ", 4) == 0) 
				p = key, line_is = KEY, cnt = &key_len, rpt = &rpt_cnt;
			else if(strncmp(line, "IV  ", 4) == 0) 
				p = iv,  line_is = IV,  cnt = &iv_len, rpt = &rpt_cnt;
			else if(strncmp(line, "HDR ", 4) == 0) 
				p = hdr, line_is = HDR, cnt = &hdr_len, rpt = &hdr_rpt;
			else if(strncmp(line, "PTX ", 4) == 0) 
				p = ptx, line_is = PTX, cnt = &ptx_len, rpt = &ptx_rpt;
			else if(strncmp(line, "CTX ", 4) == 0) 
				p = ctx, line_is = CTX, cnt = &ctx_len, rpt = &rpt_cnt;
			else if(strncmp(line, "TAG ", 4) == 0) 
				p = tag, line_is = TAG, cnt = &tag_len, rpt = &rpt_cnt;
			else
			{
				printf("\nThe test vector file contains an unrecognised line");
				break;
				
			}

			if(line[strlen(line) - 1] == '\n' || line[strlen(line) - 1] == '\r')
				line[strlen(line) - 1] = '\0';
			if(line_is != CTX && line_is != TAG)
				fprintf(outf, "\n%s", line);

			lp = line + 4;
			while(*lp != '\n' && *lp != '\0' && *(lp + 1) != '\n' && *(lp + 1) != '\0')
			{	
				p[(*cnt)++] = hex_in(lp); lp += 2;
			}

			if(line_is != TAG)
				continue;

			f->init_and_key(key, key_len, contx);

			if(strcmp(f->name, "CCM") == 0)
				((s_init_message*)f->init_message)(iv, iv_len, 
					hdr_len * hdr_rpt, ptx_len * ptx_rpt, tag_len, contx);
			else
				f->init_message(iv, iv_len, contx);
			
			i = hdr_rpt;
			while(i--)
				f->auth_header(hdr, hdr_len, contx);

			i = ptx_rpt;
			while(i--)
			{
				memcpy(buf, ptx, ptx_len);
				f->encrypt(buf, ptx_len, contx);
			}

			f->compute_tag(tbuf, tag_len, contx);

			f->end(contx);
			
			for(i = 0; i < ptx_len; ++i)
			{
				if(i % 32 == 0) fprintf(outf, "\nCTX ");
				fprintf(outf, "%02x", buf[i]);
			}

			for(i = 0; i < tag_len; ++i)
			{
				if(i % 32 == 0) fprintf(outf, "\nTAG ");
				fprintf(outf, "%02x", tbuf[i]);
			}

			f->init_and_key(key, key_len, contx);

			if(strcmp(f->name, "CCM") == 0)
				((s_init_message*)f->init_message)(iv, iv_len, 
					hdr_len * hdr_rpt, ptx_len * ptx_rpt, tag_len, contx);
			else
				f->init_message(iv, iv_len, contx);

			i = hdr_rpt;
			while(i--)
				f->auth_header(hdr, hdr_len, contx);

			i = ptx_rpt;
			while(i--)
			{
				f->decrypt(buf, ptx_len, contx);
			}

			f->compute_tag(tbuf, tag_len, contx);

			f->end(contx);
			
			if(ptx_rpt == 1 && memcmp(ptx, buf, ptx_len))
				printf("\nciphertext error on test number %i", vec_no), err++;
			if(memcmp(tag, tbuf, tag_len))
				printf("\ntag error on test number %i", vec_no), err++;
		}

		if(!err)
			printf("\nCorrect result for the tests in \"%s\"", tvi_name); 
		if(inf) fclose(inf); 
		if(outf) fclose(outf); 
	}

	return;
}

void do_test(mode_fns f[1], void* contx)
{	char			tvi_name[64], line[80], buf[256], tbuf[16], *lp;
	FILE			*inf = 0;
	unsigned char	key[32], iv[256], hdr[256], ptx[256], ctx[256], tag[16], *p;
	int				key_len, iv_len, hdr_len, ptx_len, ctx_len, tag_len,
					hdr_rpt, ptx_rpt, rpt_cnt, vec_no, *cnt, *rpt, err, i;
	enum line_ty	line_is;

	strcpy(tvi_name, in_dir);
	strcat(tvi_name, f->name);
	strcat(tvi_name, ".0");

	for( ; ; )
	{
		tvi_name[strlen(tvi_name) - 1]++;

		if(!(inf = fopen(tvi_name, "r")))
			break;

		do
		{
			fgets(line, 80, inf);
		}
		while
            (strncmp(line, "MDE ", 4) != 0);

		if(feof(inf))
			break;

		if(strncmp(line + 4, f->name, 3) != 0)
		{
			printf("\nThe test vector file does not match %s", f->name);
			break;
		}

		for(err = 0; ; )
		{
			fgets(line, 80, inf);

			if(strlen(line) < 4)
			{
				key_len = iv_len = hdr_len = ptx_len = 
					ctx_len = tag_len = rpt_cnt = 0;
				hdr_rpt = ptx_rpt = 1;
				continue;
			}
			
			if(feof(inf))
				break;

			if(strncmp(line, "VEC ", 4) == 0)
			{
				vec_no = dec_in(line + 4);
				continue;			
			}
			else if(strncmp(line, "RPT ", 4) == 0)
			{
				*rpt = dec_in(line + 4);
				continue;
			}
			else if(strncmp(line, "KEY ", 4) == 0) 
				p = key, line_is = KEY, cnt = &key_len, rpt = &rpt_cnt;
			else if(strncmp(line, "IV  ", 4) == 0) 
				p = iv,  line_is = IV,  cnt = &iv_len, rpt = &rpt_cnt;
			else if(strncmp(line, "HDR ", 4) == 0) 
				p = hdr, line_is = HDR, cnt = &hdr_len, rpt = &hdr_rpt;
			else if(strncmp(line, "PTX ", 4) == 0) 
				p = ptx, line_is = PTX, cnt = &ptx_len, rpt = &ptx_rpt;
			else if(strncmp(line, "CTX ", 4) == 0) 
				p = ctx, line_is = CTX, cnt = &ctx_len, rpt = &rpt_cnt;
			else if(strncmp(line, "TAG ", 4) == 0) 
				p = tag, line_is = TAG, cnt = &tag_len, rpt = &rpt_cnt;
			else
			{
				printf("\nThe test vector file contains an unrecognised line");
				break;
				
			}

			lp = line + 4;
			while(*lp != '\n' && *lp != '\0' && *(lp + 1) != '\n' && *(lp + 1) != '\0')
			{	
				p[(*cnt)++] = hex_in(lp); lp += 2;
			}

			if(line_is != TAG)
				continue;

			f->init_and_key(key, key_len, contx);

			if(strcmp(f->name, "CCM") == 0)
				((s_init_message*)f->init_message)(iv, iv_len, 
					hdr_len * hdr_rpt, ptx_len * ptx_rpt, tag_len, contx);
			else
				f->init_message(iv, iv_len, contx);
			
			i = hdr_rpt;
			while(i--)
				f->auth_header(hdr, hdr_len, contx);

			i = ptx_rpt;
			while(i--)
			{
				memcpy(buf, ptx, ptx_len);
				f->encrypt(buf, ptx_len, contx);
			}

			f->compute_tag(tbuf, tag_len, contx);

			f->end(contx);
			
			if(ptx_rpt == 1 && memcmp(ctx, buf, ptx_len))
				printf("\nciphertext error on test number %i", vec_no), err++;
			if(memcmp(tag, tbuf, tag_len))
				printf("\ntag error on test number %i", vec_no), err++;

			f->init_and_key(key, key_len, contx);

			if(strcmp(f->name, "CCM") == 0)
				((s_init_message*)f->init_message)(iv, iv_len, 
					hdr_len * hdr_rpt, ptx_len * ptx_rpt, tag_len, contx);
			else
				f->init_message(iv, iv_len, contx);

			i = hdr_rpt;
			while(i--)
				f->auth_header(hdr, hdr_len, contx);

			i = ptx_rpt;
			while(i--)
			{
				f->decrypt(buf, ptx_len, contx);
			}

			f->compute_tag(tbuf, tag_len, contx);

			f->end(contx);
			
			if(ptx_rpt == 1 && memcmp(ptx, buf, ptx_len))
				printf("\nciphertext error on test number %i", vec_no), err++;
			if(memcmp(tag, tbuf, tag_len))
				printf("\ntag error on test number %i", vec_no), err++;
		}

		if(!err)
			printf("\n%s test vectors in \"%s\" matched", f->name, tvi_name); 
		if(inf) fclose(inf); 
	}

	return;
}

const unsigned int loops = 100; // number of timing loops

unsigned int rand32(void)
{   static unsigned int   r4,r_cnt = -1,w = 521288629,z = 362436069;

    z = 36969 * (z & 65535) + (z >> 16);
    w = 18000 * (w & 65535) + (w >> 16);

    r_cnt = 0; r4 = (z << 16) + w; return r4;
}

unsigned char rand8(void)
{   static unsigned int   r4,r_cnt = 4;

    if(r_cnt == 4)
    {
        r4 = rand32(); r_cnt = 0;
    }

    return (char)(r4 >> (8 * r_cnt++));
}

// fill a block with random charactrers

void block_rndfill(unsigned char l[], unsigned int len)
{   unsigned int  i;

    for(i = 0; i < len; ++i)

        l[i] = rand8();
}

double CCM_time(int key_len, int iv_len, int hdr_len, int txt_len)
{   int    i, c1 = INT_MAX, c2 = INT_MAX, cy1, cy2, err;
    unsigned volatile long long tval;
    unsigned char   t1[BLOCK_SIZE], t2[BLOCK_SIZE], t3[BLOCK_SIZE];
    CCM_ctx			ctx[1];

    unsigned char *kp = malloc(key_len);
    unsigned char *ip = malloc(iv_len);
    unsigned char *hp = malloc(hdr_len);
    unsigned char *tp = malloc(txt_len);
    unsigned char *bp1 = malloc(txt_len);
    unsigned char *bp2 = malloc(txt_len);
    unsigned char *bp3 = malloc(txt_len);
    block_rndfill(kp, key_len);
    block_rndfill(ip, iv_len);
    block_rndfill(hp, hdr_len);
    block_rndfill(tp, txt_len);

    CCM_init_and_key(kp, key_len, ctx);

    for(i = 0; i < loops; ++i)
    {
        memcpy(bp1, tp, txt_len);
        memcpy(bp2, tp, txt_len);
        memcpy(bp3, tp, txt_len);
        err = 0;

		start_timer(tval);
        CCM_encrypt_message(ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx);
		cy1 = stop_timer(tval);

		start_timer(tval);
        CCM_encrypt_message(ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx);
        CCM_encrypt_message(ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx);
		cy2 = stop_timer(tval);

        err |=  CCM_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx) == FAILURE
             || memcmp(bp1, tp, txt_len);

        err |=  CCM_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx) == FAILURE
             || memcmp(bp2, tp, txt_len);

        err |=  CCM_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx) == FAILURE
             || memcmp(bp3, tp, txt_len);

        if(err) printf("\n error");
        c1 = (unsigned int)(c1 > cy1 ? cy1 : c1);
        c2 = (unsigned int)(c2 > cy2 ? cy2 : c2);
    }

    CCM_end(ctx);
    free(kp); free(ip);
    free(hp); free(tp);
    free(bp1); free(bp2); free(bp3);

    return ((c2 - c1) + 0.5);
}

double CWC_time(int key_len, int iv_len, int hdr_len, int txt_len)
{   int    i, c1 = INT_MAX, c2 = INT_MAX, cy1, cy2, err;
    unsigned volatile long long tval;
    unsigned char   t1[BLOCK_SIZE], t2[BLOCK_SIZE], t3[BLOCK_SIZE];
    CWC_ctx			ctx[1];

    unsigned char *kp = malloc(key_len);
    unsigned char *ip = malloc(iv_len);
    unsigned char *hp = malloc(hdr_len);
    unsigned char *tp = malloc(txt_len);
    unsigned char *bp1 = malloc(txt_len);
    unsigned char *bp2 = malloc(txt_len);
    unsigned char *bp3 = malloc(txt_len);
    block_rndfill(kp, key_len);
    block_rndfill(ip, iv_len);
    block_rndfill(hp, hdr_len);
    block_rndfill(tp, txt_len);

    CWC_init_and_key(kp, key_len, ctx);

    for(i = 0; i < loops; ++i)
    {
        memcpy(bp1, tp, txt_len);
        memcpy(bp2, tp, txt_len);
        memcpy(bp3, tp, txt_len);
        err = 0;

		start_timer(tval);
        CWC_encrypt_message(ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx);
		cy1 = stop_timer(tval);

		start_timer(tval);
        CWC_encrypt_message(ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx);
        CWC_encrypt_message(ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx);
		cy2 = stop_timer(tval);

        err |=  CWC_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx) == FAILURE
             || memcmp(bp1, tp, txt_len);

        err |=  CWC_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx) == FAILURE
             || memcmp(bp2, tp, txt_len);

        err |=  CWC_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx) == FAILURE
             || memcmp(bp3, tp, txt_len);

        if(err) printf("\n error");
        c1 = (unsigned int)(c1 > cy1 ? cy1 : c1);
        c2 = (unsigned int)(c2 > cy2 ? cy2 : c2);
    }

    CWC_end(ctx);
    free(kp); free(ip);
    free(hp); free(tp);
    free(bp1); free(bp2); free(bp3);

    return ((c2 - c1) + 0.5);
}

double EAX_time(int key_len, int iv_len, int hdr_len, int txt_len)
{   int    i, c1 = INT_MAX, c2 = INT_MAX, cy1, cy2, err;
    unsigned volatile long long tval;
    unsigned char   t1[BLOCK_SIZE], t2[BLOCK_SIZE], t3[BLOCK_SIZE];
    EAX_ctx			ctx[1];

    unsigned char *kp = malloc(key_len);
    unsigned char *ip = malloc(iv_len);
    unsigned char *hp = malloc(hdr_len);
    unsigned char *tp = malloc(txt_len);
    unsigned char *bp1 = malloc(txt_len);
    unsigned char *bp2 = malloc(txt_len);
    unsigned char *bp3 = malloc(txt_len);
    block_rndfill(kp, key_len);
    block_rndfill(ip, iv_len);
    block_rndfill(hp, hdr_len);
    block_rndfill(tp, txt_len);

    EAX_init_and_key(kp, key_len, ctx);

    for(i = 0; i < loops; ++i)
    {
        memcpy(bp1, tp, txt_len);
        memcpy(bp2, tp, txt_len);
        memcpy(bp3, tp, txt_len);
        err = 0;

		start_timer(tval);
        EAX_encrypt_message(ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx);
		cy1 = stop_timer(tval);

		start_timer(tval);
        EAX_encrypt_message(ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx);
        EAX_encrypt_message(ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx);
		cy2 = stop_timer(tval);

        err |=  EAX_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx) == FAILURE
             || memcmp(bp1, tp, txt_len);

        err |=  EAX_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx) == FAILURE
             || memcmp(bp2, tp, txt_len);

        err |=  EAX_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx) == FAILURE
             || memcmp(bp3, tp, txt_len);

        if(err) printf("\n error");
        c1 = (unsigned int)(c1 > cy1 ? cy1 : c1);
        c2 = (unsigned int)(c2 > cy2 ? cy2 : c2);
    }

    EAX_end(ctx);
    free(kp); free(ip);
    free(hp); free(tp);
    free(bp1); free(bp2); free(bp3);

    return ((c2 - c1) + 0.5);
}

double GCM_time(int key_len, int iv_len, int hdr_len, int txt_len)
{   int    i, c1 = INT_MAX, c2 = INT_MAX, cy1, cy2, err;
    unsigned volatile long long tval;
    unsigned char   t1[BLOCK_SIZE], t2[BLOCK_SIZE], t3[BLOCK_SIZE];
    GCM_ctx			ctx[1];

    unsigned char *kp = malloc(key_len);
    unsigned char *ip = malloc(iv_len);
    unsigned char *hp = malloc(hdr_len);
    unsigned char *tp = malloc(txt_len);
    unsigned char *bp1 = malloc(txt_len);
    unsigned char *bp2 = malloc(txt_len);
    unsigned char *bp3 = malloc(txt_len);
    block_rndfill(kp, key_len);
    block_rndfill(ip, iv_len);
    block_rndfill(hp, hdr_len);
    block_rndfill(tp, txt_len);

    GCM_init_and_key(kp, key_len, ctx);

    for(i = 0; i < loops; ++i)
    {
        memcpy(bp1, tp, txt_len);
        memcpy(bp2, tp, txt_len);
        memcpy(bp3, tp, txt_len);
        err = 0;

		start_timer(tval);
        GCM_encrypt_message(ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx);
		cy1 = stop_timer(tval);

		start_timer(tval);
        GCM_encrypt_message(ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx);
        GCM_encrypt_message(ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx);
		cy2 = stop_timer(tval);

        err |=  GCM_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp1, txt_len, t1, 16, ctx) == FAILURE
             || memcmp(bp1, tp, txt_len);

        err |=  GCM_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp2, txt_len, t2, 16, ctx) == FAILURE
             || memcmp(bp2, tp, txt_len);

        err |=  GCM_decrypt_message
                  (ip, iv_len, hp, hdr_len, bp3, txt_len, t3, 16, ctx) == FAILURE
             || memcmp(bp3, tp, txt_len);

        if(err) printf("\n error");
        c1 = (unsigned int)(c1 > cy1 ? cy1 : c1);
        c2 = (unsigned int)(c2 > cy2 ? cy2 : c2);
    }

    GCM_end(ctx);
    free(kp); free(ip);
    free(hp); free(tp);
    free(bp1); free(bp2); free(bp3);

    return ((c2 - c1) + 0.5);
}

static int tlen[12] = { 16, 20, 40, 44, 64, 128, 256, 552, 576, 1024, 1500, 8192 };

void CCM_tests(unsigned long key_len, unsigned long iv_len, 
								unsigned long hdr_len, double tval[])
{	CCM_ctx	ctx[1];
	mode_fns f[1];
	int i;

	CCM_functions(f);
	do_test(f, ctx);
	for(i = 0; i < 12; ++i)
		tval[i] = CCM_time(key_len, iv_len, hdr_len, tlen[i]);
}

void CWC_tests(unsigned long key_len, unsigned long iv_len, 
								unsigned long hdr_len, double tval[])
{	CWC_ctx	ctx[1];
	mode_fns f[1];
	int	i;

	CWC_functions(f);
	do_test(f, ctx);
	for(i = 0; i < 12; ++i)
		tval[i] = CWC_time(key_len, iv_len, hdr_len, tlen[i]);
}

void EAX_tests(unsigned long key_len, unsigned long iv_len, 
								unsigned long hdr_len, double tval[])
{	EAX_ctx	ctx[1];
	mode_fns f[1];
	int	i;

	EAX_functions(f);
	do_test(f, ctx);
	for(i = 0; i < 12; ++i)
		tval[i] = EAX_time(key_len, iv_len, hdr_len, tlen[i]);
}

void GCM_tests(unsigned long key_len, unsigned long iv_len, 
								unsigned long hdr_len, double tval[])
{	GCM_ctx	ctx[1];
	mode_fns f[1];
	int	i;

	GCM_functions(f);
	do_test(f, ctx);
	for(i = 0; i < 12; ++i)
		tval[i] = GCM_time(key_len, iv_len, hdr_len, tlen[i]);
}

int main(void)
{
	mode_fns f[1];
	double tval[4][13];
	unsigned long hdr_len = 0;
	int		i;

	CCM_tests(16, 12, hdr_len, tval[0]);
	CWC_tests(16, 12, hdr_len, tval[1]);
	EAX_tests(16, 12, hdr_len, tval[2]);
	GCM_tests(16, 12, hdr_len, tval[3]);

	for(i = 0; i < 4; ++i)
	{	double av;
	    av = 0.05 * tval[i][3] + 0.15 * tval[i][7] 
					+ 0.2 * tval[i][8] + 0.6 * tval[i][10];
	    av /= (0.05 * 44 + 0.15 * 552 + 0.2 * 576 + 0.6 * 1500 + hdr_len);
		tval[i][12] = av;
	}

	printf("\n\n  Length      CCM      CWC      EAX      GCM");
	for(i = 0; i < 12; ++i)
	{
		printf("\n%8i %8.2f %8.2f %8.2f %8.2f", tlen[i], 
					tval[0][i] / (tlen[i] + hdr_len), 
					tval[1][i] / (tlen[i] + hdr_len), 
					tval[2][i] / (tlen[i] + hdr_len),
					tval[3][i] / (tlen[i] + hdr_len));
	}

	printf("\naverage: %8.2f %8.2f %8.2f %8.2f", 
					tval[0][12], tval[1][12], tval[2][12], tval[3][12]);

	printf("\n\n");
	return 0;
}
