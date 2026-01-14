#include <string.h>
#include <stddef.h>

void* memset(void* dest, int val, size_t len) {
    unsigned char* ptr = dest;
    while (len-- > 0)
        *ptr++ = (unsigned char)val;
    return dest;
}

void* memcpy(void* dest, const void* src, size_t len) {
    char* d = dest;
    const char* s = src;
    while (len--)
        *d++ = *s++;
    return dest;
}

size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int strncmp(const char* s1, const char* s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++; s2++; n--;
    }
    if (n == 0) return 0;
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

char* strcpy(char* dest, const char* src) {

    char* d = dest;

    while ((*d++ = *src++));

    return dest;

}



char* strncpy(char* dest, const char* src, size_t n) {

    char* d = dest;

    while (n && (*d++ = *src++)) n--;

    while (n--) *d++ = '\0';

    return dest;

}
