
#ifndef _CYCLES_H
#define _CYCLES_H

typedef unsigned long long cyc_type;

cyc_type cycles( void );

#define start_timer(x)	(x = cycles())
#define stop_timer(x)	((int)(cycles() - (x)))

#endif
