#ifndef _cygwin_sys_wait_h

#include_next <sys/wait.h>

#if !defined (WCOREDUMP)
# define WCOREDUMP(x) (((x) & 0x80) == 0x80)
#endif

#endif
