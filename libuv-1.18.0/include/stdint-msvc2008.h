#ifndef _STDINT_MSVC2008_H_
#define _STDINT_MSVC2008_H_

#if defined(_MSC_VER) && _MSC_VER >= 1600
#include <stdint.h>
#else
// ... (original content if we really wanted to keep it for old MSVC, but we can just use a guard)
#endif

#endif
