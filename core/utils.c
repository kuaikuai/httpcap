
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "error.h"

char *str_strip_whitespace(char *str) {
        size_t len = strlen(str);

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        while (isspace(*str)) str++;
        while (len && isspace(*(str + len - 1)))
                *(str + (len--) - 1) = '\0';

        return str;
}

char *str_tolower(char *str) {
        char *c;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        for (c = str; *c != '\0'; c++) {
                *c = tolower(*c);
        }

        return str;
}


int str_compare(const char *str1, const char *str2) {

#ifdef DEBUG
        ASSERT(str2);
        ASSERT(strlen(str2) > 0);
        ASSERT(str1 != str2);
#endif

        while (*str1 == *str2) {
                str1++;
                str2++;
                if (*str2 == '\0') return 0;
        }

        return tolower(*str1) - *str2;
}

int str_copy(char *dest, const char *src, size_t len) {
        const char *start = dest;

        if (len > 0) {
                while ((*src != '\0') && --len) {
                        *dest++ = *src++;
                }
                *dest = '\0';
        }

        return dest - start;
}

/* used for debug */
int str_is_ascii(char *str) {
    while (*str != '\0') {
        unsigned char ch = *str++;
        if (ch >= 0x80) {
            return 0;
        }
    }
    return 1;
}


void debug_ascii(char *uri, char *info)
{
#if 0
    /* used for testing */
    if (!str_is_ascii(uri)) {
        char tmp[256];
        snprintf(tmp, sizeof(tmp)-1, "%s found no ascii %s", uri, info);
        LOG(tmp);
    }
#endif
}

#if 0
char *str_duplicate(const char *str) {
        char *new;
        size_t len = strlen(str);

        if ((new = malloc(len + 1)) == NULL)
                return NULL;

#ifdef DEBUG
        ASSERT(str_copy(new, str, len + 1) <= (len + 1));
#else
        str_copy(new, str, len + 1);
#endif

        return new;
}
#endif
/* Implementation of Jenkins's One-at-a-Time hash, as described on
   this page: http://www.burtleburtle.net/bob/hash/doobs.html */
unsigned int hash_str(char *str, unsigned int hashsize) {
        unsigned long int hash;

#ifdef DEBUG
        ASSERT(str);
        ASSERT(strlen(str) > 0);
#endif

        for (hash = 0; *str != '\0'; str++) {
                hash += tolower(*str);
                hash += (hash << 10);
                hash ^= (hash >> 6);
        }

        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);

        /* Restrict hash value to a maximum of hashsize;
           hashsize must be a power of 2 */
        return (unsigned int) (hash & (hashsize - 1));
}
