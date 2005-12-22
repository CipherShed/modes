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

 This header file is an INTERNAL file to assist in mode implementation 
*/

#ifndef _MODE_HDR_H
#define _MODE_HDR_H

#include <memory.h>
#include <limits.h>

#if defined(__cplusplus)
extern "C"
{
#endif

/* define an unsigned 32-bit type */

#if defined(_MSC_VER)
  typedef   unsigned long    mode(32t);
#elif defined(ULONG_MAX) && ULONG_MAX == 4294967295ul
  typedef   unsigned long    mode(32t);
#elif defined(UINT_MAX) && UINT_MAX == 4294967295
  typedef   unsigned int     mode(32t);
#else
#  error mode(32t) must be an unsigned 32-bit type (see the header file)
#endif

/* define an unsigned 64-bit type (thanks to Mark Shelor and */
/* Olaf Pors for their help in developing and testing this). */

#if defined(_MSC_VER)
# if _MSC_VER < 1300
    typedef unsigned __int64   mode(64t);
# else
    typedef unsigned long long mode(64t);
# endif
#elif defined(ULONG_LONG_MAX) && ULONG_LONG_MAX == 18446744073709551615ull
  typedef unsigned long long    mode(64t);
#elif defined(ULONG_MAX) && ULONG_MAX == 18446744073709551615ul
  typedef unsigned long         mode(64t);
#elif defined(UINT_MAX) && UINT_MAX == 18446744073709551615
  typedef unsigned int          mode(64t);
#else
#  error mode(64t) must be an unsigned 64-bit type (see the header file)
#endif

/*  PLATFORM SPECIFIC INCLUDES AND BYTE ORDER IN 32-BIT WORDS

    To obtain the highest speed on processors with 32-bit words, this code
    needs to determine the byte order of the target machine. The following
    block of code is an attempt to capture the most obvious ways in which
    various environemnts define byte order. It may well fail, in which case
    the definitions will need to be set by editing at the points marked
    **** EDIT HERE IF NECESSARY **** below.  My thanks go to Peter Gutmann
    for his assistance with this endian detection nightmare.
*/

#define BRG_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
#define BRG_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

#if defined(__GNUC__) || defined(__GNU_LIBRARY__)
#  if defined(__FreeBSD__) || defined(__OpenBSD__)
#    include <sys/endian.h>
#  elif defined( BSD ) && ( BSD >= 199103 )
#      include <machine/endian.h>
#  elif defined(__APPLE__)
#    if defined(__BIG_ENDIAN__) && !defined( BIG_ENDIAN )
#      define BIG_ENDIAN
#    elif defined(__LITTLE_ENDIAN__) && !defined( LITTLE_ENDIAN )
#      define LITTLE_ENDIAN
#    endif
#  else
#    include <endian.h>
#    if !defined(__BEOS__)
#      include <byteswap.h>
#    endif
#  endif
#endif

#if !defined(PLATFORM_BYTE_ORDER)
#  if defined(LITTLE_ENDIAN) || defined(BIG_ENDIAN)
#    if    defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#    elif !defined(LITTLE_ENDIAN) &&  defined(BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#    elif defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#    elif defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#    endif
#  elif defined(_LITTLE_ENDIAN) || defined(_BIG_ENDIAN)
#    if    defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#    elif !defined(_LITTLE_ENDIAN) &&  defined(_BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#    elif defined(_BYTE_ORDER) && (_BYTE_ORDER == _LITTLE_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#    elif defined(_BYTE_ORDER) && (_BYTE_ORDER == _BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#   endif
#  elif defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__)
#    if    defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#    elif !defined(__LITTLE_ENDIAN__) &&  defined(__BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#    elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
#      define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#    elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#    endif
#  endif
#endif

/*  if the platform is still unknown, try to find its byte order    */
/*  from commonly used machine defines                              */

#if !defined(PLATFORM_BYTE_ORDER)

#if   defined( __alpha__ ) || defined( __alpha ) || defined( i386 )       || \
      defined( __i386__ )  || defined( _M_I86 )  || defined( _M_IX86 )    || \
      defined( __OS2__ )   || defined( sun386 )  || defined( __TURBOC__ ) || \
      defined( vax )       || defined( vms )     || defined( VMS )        || \
      defined( __VMS )
#  define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN

#elif defined( AMIGA )    || defined( applec )  || defined( __AS400__ )  || \
      defined( _CRAY )    || defined( __hppa )  || defined( __hp9000 )   || \
      defined( ibm370 )   || defined( mc68000 ) || defined( m68k )       || \
      defined( __MRC__ )  || defined( __MVS__ ) || defined( __MWERKS__ ) || \
      defined( sparc )    || defined( __sparc)  || defined( SYMANTEC_C ) || \
      defined( __TANDEM ) || defined( THINK_C ) || defined( __VMCMS__ )
#  define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN

#elif 0     /* **** EDIT HERE IF NECESSARY **** */
#  define PLATFORM_BYTE_ORDER BRG_LITTLE_ENDIAN
#elif 0     /* **** EDIT HERE IF NECESSARY **** */
#  define PLATFORM_BYTE_ORDER BRG_BIG_ENDIAN
#else
#  error Please edit mode_hdr.h to set the platform byte order
#endif

#endif

#ifdef _MSC_VER
#pragma intrinsic(memcpy)
#define in_line __inline
#else
#define in_line
#endif

#if 0 && defined(_MSC_VER)
#define rotl32 _lrotl
#define rotr32 _lrotr
#else
#define rotl32(x,n)   (((x) << n) | ((x) >> (32 - n)))
#define rotr32(x,n)   (((x) >> n) | ((x) << (32 - n)))
#endif

#if !defined(bswap_32)
#define bswap_32(x) (rotr32((x), 24) & 0x00ff00ff | rotr32((x), 8) & 0xff00ff00)
#endif

#if (PLATFORM_BYTE_ORDER == BRG_LITTLE_ENDIAN)
#define SWAP_BYTES
#else
#undef  SWAP_BYTES
#endif

#if defined(SWAP_BYTES)

#if defined ( IN_LINES )

in_line void bsw_32(void * p, unsigned int n)
{   unsigned int i = n;
    while(i--)
        ((mode(32t)*)p)[i] = bswap_32(((mode(32t)*)p)[i]);
}

#else

#define bsw_32(p,n) \
    { int _i = (n); while(_i--) ((mode(32t)*)p)[_i] = bswap_32(((mode(32t)*)p)[_i]); }

#endif

#else
#define bsw_32(p,n)
#endif

/* These values are used to detect long word alignment in order */
/* to speed up some GCM buffer operations. This facility may    */
/* not work on some machines                                    */

#define lp08(x)      ((unsigned char*)(x))
#define lp32(x)      ((mode(32t)*)(x))
#define lp64(x)      ((mode(64t)*)(x))

#define A32_MASK     3
#define A64_MASK     7
#define aligned32(x) (!(((mode(32t))(x)) & A32_MASK))
#define aligned64(x) (!(((mode(32t))(x)) & A64_MASK))

#if defined( BUFFER_ALIGN32 )

#define ADR_MASK    A32_MASK
#define aligned     aligned32
#define lp          lp32
#define lp_inc      4

#if defined( IN_LINES )

in_line void move_block_aligned( void *p, const void *q)
{
    lp32(p)[0] = lp32(q)[0], lp32(p)[1] = lp32(q)[1],
    lp32(p)[2] = lp32(q)[2], lp32(p)[3] = lp32(q)[3];
}

in_line void xor_block_aligned( void *p, const void *q)
{
    lp32(p)[0] ^= lp32(q)[0], lp32(p)[1] ^= lp32(q)[1],
    lp32(p)[2] ^= lp32(q)[2], lp32(p)[3] ^= lp32(q)[3];
}
#else

#define move_block_aligned(p,q) \
    lp32(p)[0] = lp32(q)[0], lp32(p)[1] = lp32(q)[1], \
    lp32(p)[2] = lp32(q)[2], lp32(p)[3] = lp32(q)[3]

#define xor_block_aligned(p,q) \
    lp32(p)[0] ^= lp32(q)[0], lp32(p)[1] ^= lp32(q)[1], \
    lp32(p)[2] ^= lp32(q)[2], lp32(p)[3] ^= lp32(q)[3]

#endif

#elif defined( BUFFER_ALIGN64 )

#define ADR_MASK    A64_MASK
#define aligned     aligned64
#define lp          lp64
#define lp_inc      8

#define move_block_aligned(p,q) \
    lp64(p)[0] = lp64(q)[0], lp64(p)[1] = lp64(q)[1]

#define xor_block_aligned(p,q) \
    lp64(p)[0] ^= lp64(q)[0], lp64(p)[1] ^= lp64(q)[1]

#else
#define aligned(x) 0
#endif

#define move_block(p,q) memcpy((p), (q), BLOCK_LEN)

#define xor_block(p,q) \
    lp08(p)[ 0] ^= lp08(q)[ 0], lp08(p)[ 1] ^= lp08(q)[ 1], \
    lp08(p)[ 2] ^= lp08(q)[ 2], lp08(p)[ 3] ^= lp08(q)[ 3], \
    lp08(p)[ 4] ^= lp08(q)[ 4], lp08(p)[ 5] ^= lp08(q)[ 5], \
    lp08(p)[ 6] ^= lp08(q)[ 6], lp08(p)[ 7] ^= lp08(q)[ 7], \
    lp08(p)[ 8] ^= lp08(q)[ 8], lp08(p)[ 9] ^= lp08(q)[ 9], \
    lp08(p)[10] ^= lp08(q)[10], lp08(p)[11] ^= lp08(q)[11], \
    lp08(p)[12] ^= lp08(q)[12], lp08(p)[13] ^= lp08(q)[13], \
    lp08(p)[14] ^= lp08(q)[14], lp08(p)[15] ^= lp08(q)[15]

#if defined(__cplusplus)
}
#endif

#endif
