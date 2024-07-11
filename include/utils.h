#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

bool isValidEmail(const char *email);
bool isStrongPassword(const char *password);
void string_to_argon2hash(const char *input_string);
void verify_argon2hash(const char *input_string, const char *hashed_string);
#endif