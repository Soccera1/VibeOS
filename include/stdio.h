#ifndef _STDIO_H
#define _STDIO_H

#include "../user/libc.h"

#include <stdarg.h>

typedef void FILE;
extern FILE *stdout;
extern FILE *stderr;
extern FILE *stdin;
#define BUFSIZ 4096
#define EOF    (-1)

int printf(const char *format, ...);
int vprintf(const char *format, va_list ap);
int fprintf(FILE *stream, const char *format, ...);
int dprintf(int fd, const char *format, ...);
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
int vasprintf(char **strp, const char *fmt, va_list ap);
int sscanf(const char *str, const char *format, ...);
int vfprintf(FILE *stream, const char *format, va_list ap);
int putchar(int c);
int puts(const char *s);
int fputc(int c, FILE *stream);
int putc_unlocked(int c, FILE *stream);
int getc_unlocked(FILE *stream);
int fputs(const char *s, FILE *stream);
char *fgets(char *s, int size, FILE *stream);
FILE *fopen(const char *pathname, const char *mode);
FILE *fdopen(int fd, const char *mode);
void clearerr(FILE *stream);
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
int fgetc(FILE *stream);
int fputc(int c, FILE *stream);
int getc_unlocked(FILE *stream);
int putc_unlocked(int c, FILE *stream);
int fclose(FILE *stream);
int fflush(FILE *stream);
int ferror(FILE *stream);
int fileno(FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fseeko(FILE *stream, off_t offset, int whence);
FILE *freopen(const char *pathname, const char *mode, FILE *stream);

int putchar_unlocked(int c);
int puts_unlocked(const char *s);
int fputs_unlocked(const char *s, FILE *stream);
int fgets_unlocked(char *s, int n, FILE *stream);
int ferror_unlocked(FILE *stream);
int fileno_unlocked(FILE *stream);

#endif
