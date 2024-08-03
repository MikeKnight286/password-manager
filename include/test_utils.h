#ifndef TEST_UTILS_H
#define TEST_UTILS_H

void test_isValidName(); // Test name input validation
void test_isValidEmail(); // Test email input validation
void test_isStrongPassword(); // Test password strength
void test_argon2hash(); // Test argon2 hash and verification of the password with the hash
void test_isValidImage(const char *image_path); // Test if it is an acceptable image file
void test_generate_fingerprint_and_key_from_image(const char *image_path_1, const char *image_path_2); // Test generating fingerprints and keys from images and compare if same fingerprint is produced when used same images by different users
void test_generate_key_from_password(); // Test generating key from password

#endif