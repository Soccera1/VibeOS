#ifndef _FNMATCH_H
#define _FNMATCH_H
#define FNM_PATHNAME 0
#define FNM_PERIOD   0
#define FNM_NOMATCH  1
int fnmatch(const char *pattern, const char *string, int flags);
#endif
