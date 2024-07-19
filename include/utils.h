#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

bool isValidName(const char *name);
bool isValidEmail(const char *email);
bool isStrongPassword(const char *password);
void string_to_argon2hash(const char *input_string, char *hashed_string);
bool verify_argon2hash(const char *input_string, const char *hashed_string);
bool isValidImage(const char *image_path, char *output_path);

#endif