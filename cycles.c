/*
 * CPU counter cycle code from the FFTW library (http://www.fftw.org)
 */

#include "cycles.h"

#if defined(_MSC_VER) && defined(_M_IX86) || defined(__WATCOMC__)

cyc_type cycles( void )
{	volatile cyc_type tsc;

    __asm
    {	rdtsc
        lea     ecx,[tsc]
        mov     [ecx],eax
        mov     [ecx+4],edx
    }
    return( tsc );
}

#endif

#if defined(__i386__)

cyc_type cycles( void )
{
    volatile cyc_type tsc;
    asm volatile( "rdtsc" : "=A" (tsc) );
    return( tsc );
}

#endif

#if defined(__sparc__)

cyc_type cycles( void )
{
    unsigned long tick;
    asm volatile( "rd %%tick, %0" : "=r" (tick) );
    return( tick );
}

#endif

#if defined(__alpha__)

cyc_type cycles( void )
{
    unsigned long cc;
    asm volatile( "rpcc %0" : "=r" (cc) );
    return( cc & 0xFFFFFFFF );
}

#endif

#if defined(__x86_64__)

cyc_type cycles( void )
{
    unsigned long a, d;
    asm volatile( "rdtsc" : "=a" (a), "=d" (d) ); 
    return( ( (cyc_type) d ) << 32 | a );
}

#endif

#if defined(__ia64__)

cyc_type cycles( void )
{
    cyc_type itc;
    asm volatile( "mov %0 = ar.itc" : "=r" (itc) );
    return( itc );
}

#endif

#if defined(__powerpc__) || defined(__ppc__)

cyc_type cycles( void )
{
    unsigned long tbl, tbu0, tbu1;
    do
    {
        asm volatile( "mftbu %0" : "=r" (tbu0) );
        asm volatile( "mftb %0"  : "=r" (tbl)  );
        asm volatile( "mftbu %0" : "=r" (tbu1) );
    }
    while( tbu0 != tbu1 );
    return( ( (cyc_type) tbu0 ) << 32 | tbl );
}

#endif
