#include <stdio.h>
#include "test_libs.h"
#include "test_utils.h"

int main() {
    const char *png_file_name = "test.png"; 
    const char *jpeg_file_name = "test.jpg"; 
    const char *input_string = "test";
    char *encrypted_image = "cipher_encrypted.png";
    char img_key[32];
    char pwd_key[32];

    // printf("Testing libsodium argon2 hash function...\n");
    // argon2_hash_string(input_string);
    // printf("\n");

    // printf("Testing png image display function in CLI...\n");
    // display_png_info_CLI(png_file_name);
    // printf("\n");

    // printf("Testing png image display function in GUI...\n");
    // display_image_GUI(png_file_name);
    // printf("\n");

    // printf("Testing jpeg image display function in CLI...\n");
    // display_jpeg_info(jpeg_file_name);
    // printf("\n");

    // printf("Testing jpeg image display function in GUI...\n");
    // display_image_GUI(jpeg_file_name);
    // printf("\n");

    // printf("Testing isValidName function...\n");
    // test_isValidName();
    // printf("\n");
    
    // printf("Testing isValidEmail function...\n");
    // test_isValidEmail();
    // printf("\n");

    printf("Testing isStrongPassword function...\n");
    test_isStrongPassword();
    printf("\n");

    // printf("Testing Argon2 hash function...\n");
    // test_argon2hash();
    // printf("\n");

    // printf("Testing generate_fingerprint and generate_key from image functions...\n");
    // test_generate_fingerprint_and_key_from_image(png_file_name, png_file_name, img_key); // Testing same image by different users
    // printf("\n"); 
    // test_generate_fingerprint_and_key_from_image(png_file_name, jpeg_file_name, img_key);// Testing different image by different users
    // printf("\n");

    // printf("Testing generate_key_from_password function...\n");
    // test_generate_key_from_password(pwd_key);
    // printf("\n");

    // printf("Testing encrypting and decrypting data directly...\n");
    // test_encrypt_decrypt_data(pwd_key, img_key);
    // printf("\n");

    // printf("Testing embedding and extracting data from image...\n");
    // test_embed_extract_data_from_image();
    // printf("\n");

    // printf("Testing encrypting and decrypting data from image...\n");
    // test_encrypt_decrypt_data_from_image(pwd_key, img_key, png_file_name, encrypted_image);
    // printf("\n");

    printf("Testing generate random password function...\n");
    test_generate_random_password();
    printf("\n");
    return 0;
}