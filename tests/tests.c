#include <stdio.h>
#include "test_libs.h"
#include "test_utils.h"

int main() {
    const char *png_file_name = "test.png"; 
    const char *jpeg_file_name = "test.jpg"; 
    const char *input_string = "test";
    const char *valid_image_test_file = "jpg_to_change.jpg";

    printf("Testing libsodium argon2 hash function...\n");
    argon2_hash_string(input_string);
    printf("\n");

    printf("Testing png image display function in CLI...\n");
    display_png_info_CLI(png_file_name);
    printf("\n");

    printf("Testing png image display function in GUI...\n");
    display_image_GUI(png_file_name);
    printf("\n");

    printf("Testing jpeg image display function in CLI...\n");
    display_jpeg_info(jpeg_file_name);
    printf("\n");

    printf("Testing jpeg image display function in GUI...\n");
    display_image_GUI(jpeg_file_name);
    printf("\n");
    
    printf("Testing isValidEmail function...\n");
    test_isValidEmail();
    printf("\n");

    printf("Testing isStrongPassword function...\n");
    test_isStrongPassword();
    printf("\n");

    printf("Testing Argon2 hash function...\n");
    test_argon2hash();
    printf("\n");

    printf("Testing isValidImage function...\n");
    test_isValidImage(valid_image_test_file);
    
    return 0;
}