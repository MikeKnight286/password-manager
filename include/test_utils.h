#ifndef TEST_UTILS_H
#define TEST_UTILS_H

void test_isValidName(); // Test name input validation
void test_isValidEmail(); // Test email input validation
void test_isStrongPassword(); // Test password strength
void test_argon2hash(); // Test argon2 hash and verification of the password with the hash
void test_generate_fingerprint_and_key_from_image(const char *image_path_1, const char *image_path_2, char *image_key); // Test generating fingerprints and keys from images and compare if same fingerprint is produced when used same images by different users
void test_generate_key_from_password(char *pwd_key); // Test generating key from password
void test_encrypt_decrypt_data(const char *pwd_key, const char *img_key); // Test encrypting and decrypting data directly
void test_embed_extract_data_from_image();
void test_encrypt_decrypt_data_from_image(const char *pwd_key, const char *img_key, const char *input_image, char *output_image); // Test encrypting and decrypting data from images
void test_generate_random_password(); // Test generating random password given username and domain
#endif