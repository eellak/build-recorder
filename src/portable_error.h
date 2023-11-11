#include	"config.h"

#ifdef HAVE_ERROR_H
#include	<error.h>
#else

void error(int status, int errnum, const char *format, ...);

#endif
