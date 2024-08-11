#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

void initialize_sdl2_img();
bool convertImagetoPNG(const char *input_path, const char *png_path);
bool isValidName(const char *name);
bool isValidEmail(const char *email);
bool isStrongPassword(const char *password);
void string_to_argon2hash(const char *input_string, char *hashed_string);
bool verify_argon2hash(const char *input_string, const char *hashed_string);
void generate_fingerprint_from_image(const char *input_image, const char *user_id, const char *user_email, char *image_fingerprint);
void generate_key_from_image_fingerprint(const char *image_fingerprint, char *key, size_t key_len);
void generate_key_from_password(const char *password, char *key, size_t key_len);
void encrypt_data(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len);
void decrypt_data(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len);
void encrypt_credentials_into_image(const char *master_password_key, const char *master_image_key, const char *account_username, const char *account_domain, const char *account_pwd, const char *input_image, char *output_image);
void decrypt_credentials_from_image(const unsigned char *master_password_key, const unsigned char *master_image_key, const char *input_image, char *account_username, char *account_domain, char *account_pwd);

#endif