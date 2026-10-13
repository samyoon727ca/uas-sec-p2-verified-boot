/* Host stand-in for NuttX's arch.h: PX4's boot-loader crypto.c needs only up_assert(). */
#pragma once

#include <stdio.h>
#include <stdlib.h>

static inline void up_assert(const char *file, int line)
{
	fprintf(stderr, "up_assert at %s:%d\n", file, line);
	abort();
}
