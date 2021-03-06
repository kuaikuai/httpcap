
#ifndef _HAVE_UTILITY_H
#define _HAVE_UTILITY_H

char *str_strip_whitespace(char *str);
char *str_tolower(char *str);
int str_compare(const char *str1, const char *str2);
int str_copy(char *dest, const char *src, size_t len);
char *str_duplicate(const char *str);
unsigned int hash_str(char *key, unsigned int hashsize);
int str_is_ascii(char *str);
void debug_ascii(char *uri, char *info);
#endif /* ! _HAVE_UTILITY_H */
