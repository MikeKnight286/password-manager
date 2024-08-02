#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

bool isValidName(const char *name);
bool isValidEmail(const char *email);
bool isStrongPassword(const char *password);
void string_to_argon2hash(const char *input_string, char *hashed_string);
bool verify_argon2hash(const char *input_string, const char *hashed_string);
void generate_fingerprint_from_image(const char *input_image, const char *user_id, const char *user_email, char *image_fingerprint);
void generate_key_from_image_fingerprint(const char *image_fingerprint, char *key, size_t key_len);
void generate_key_from_password(const char *password, char *key, size_t key_len);
bool isValidImage(const char *image_path, char *output_path);

#endif