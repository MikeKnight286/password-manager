#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include "utils.h"
#include "test_utils.h"

void test_isValidName(){
    const char *valid_names[] = {
        "John Doe",
        "Émilie du Châtelet",
        "Mary-Jane O'Neil"
    };

    const char *invalid_names[] ={
        "InV@lid Name",
        "12345",
        " "
    };

    for(int i=0; i<sizeof(valid_names)/sizeof(valid_names[0]); i++){
        if(isValidName(valid_names[i])){
            printf("Valid name passed: %s\n", valid_names[i]);
        } else {
            printf("Valid name failed: %s\n", valid_names[i]);
        }
    }

    for(int i=0; i<sizeof(invalid_names)/sizeof(invalid_names[0]); i++){
        if(isValidName(invalid_names[i])){
            printf("Invalid name passed: %s\n", invalid_names[i]);
        } else {
            printf("Invalid name failed: %s\n", invalid_names[i]);
        }
    }

}

void test_isValidEmail(){
    const char *valid_emails[] = {
        "test@example.com",
        "user.name@domain.co",
        "user_name@domain.com",
        "user-name@domain.org",
        "user+name@domain.net"
    };
    const char *invalid_emails[] = {
        "testexample.com",
        "user@domain,com",
        "user@domain",
        "user@domain..com",
        "user@.domain.com"
    };

    printf("Testing isValidEmail funciton...\n");
    for (int i=0; i<sizeof(valid_emails) / sizeof(valid_emails[0]); i++){
        if(isValidEmail(valid_emails[i])){
            printf("Valid email passed: %s\n", valid_emails[i]);
        } else {
            printf("Valid email failed: %s\n", valid_emails[i]);
        }
    }

    for (int i = 0; i < sizeof(invalid_emails) / sizeof(invalid_emails[0]); i++){
        if(isValidEmail(invalid_emails[i])){
            printf("Invalid email passed: %s\n", invalid_emails[i]);
        } else {
            printf("Invalid email failed: %s\n", invalid_emails[i]);
        }
    }
}

void test_isStrongPassword(){
    const char *strong_passwords[] = {
        "ThatBrutalXXNinja280901",
        "AmberTreePunchesCars00#4",
        "superDuperdumpsterhe11a!",
        "CrimsonDuckSaysComputer0$57",
        "AzureSharkCleans*otel0943"
    };
    const char *weak_passwords[] = {
        "password",
        "123456",
        "abc",
        "mypassword",
        "2444666668888888999999999"
    };

    printf("Testing strong passwords...\n");
    for(int i=0; i < sizeof(strong_passwords) / sizeof(strong_passwords[0]); i++){
        bool result = isStrongPassword(strong_passwords[i]);
        if(result){
            printf("Strong password passed: %s\n", strong_passwords[i]);
        } else {
            printf("Strong password failed: %s\n", strong_passwords[i]);
        }
        printf("\n");
    }

    printf("Testing weak passwords...\n");
    for (int i=0; i < sizeof(weak_passwords) / sizeof(weak_passwords[0]); i++){
        bool result = isStrongPassword(weak_passwords[i]);
        if(result){
            printf("Weak password passed: %s\n", weak_passwords[i]);
        } else {
            printf("Weak password_failed %s\n", weak_passwords[i]);
        }
        printf("\n");
    }
}

void test_argon2hash(){
    const char *password = "My$3cureP@ssword";
    char hashed_password[crypto_pwhash_STRBYTES];

    string_to_argon2hash(password, hashed_password);
    printf("Hashed password: %s\n", hashed_password);

    printf("Testing Argon2 hash verification funtion...\n");
    if(verify_argon2hash(password, hashed_password)){
        printf("Verification succeeded.\n");
    } else {
        printf("Verification failed.\n");
    }
}

void test_generate_fingerprint_and_key_from_image(const char *image_path_1, const char *image_path_2, char *image_key) {
    // Hardcoded user details for testing
    const char *user_id_1 = "userTest1";
    const char *user_email_1 = "user1@example.com";
    const char *user_id_2 = "userTest2";
    const char *user_email_2 = "user2@example.com";

    char image_fingerprint_1[65];
    char image_fingerprint_2[65];
    char key[32];

    // Generate fingerprints for both images
    generate_fingerprint_from_image(image_path_1, user_id_1, user_email_1, image_fingerprint_1);
    generate_fingerprint_from_image(image_path_2, user_id_2, user_email_2, image_fingerprint_2);

    // printf("Fingerprint generated from image_path_1: %s\n", image_fingerprint_1);
    // printf("Fingerprint generated from image_path_2: %s\n", image_fingerprint_2);

    // Compare fingerprints
    // if (strcmp(image_fingerprint_1, image_fingerprint_2) == 0) {
    //     printf("Different users with the same image have matching fingerprints. Test failed.\n");
    // } else {
    //     printf("Different users with the same image have different fingerprints. Test passed.\n");
    // }

    // Generate key from the first image fingerprint
    generate_key_from_image_fingerprint(image_fingerprint_1, (char *)key, sizeof(key));
    // printf("Key generated from image_path_1: ");
    // for (int i = 0; i < sizeof(key); i++) {
    //     printf("%02x", key[i]);
    // }
    memcpy(image_key, key, sizeof(key));
    printf("\n");
}

void test_generate_key_from_password(char *pwd_key){
    char password_string[] = "ThatBrutalXXNinja280901";
    char key[32];
    // generate_key_from_password(password_string, (char *)key, sizeof(key));
    // printf("Key generated from test_password: ");
    // for (int i = 0; i < sizeof(key); i++) {
    //     printf("%02x", key[i]);
    // }
    memcpy(pwd_key, key, sizeof(key));
    printf("\n");
}

void test_encrypt_decrypt_data(const char *pwd_key, const char *img_key) {
    const char *account_username = "test_username";
    const char *account_domain = "test_domain.com";
    const char *account_password = "ThatBrutalXXNinja280901!";

    unsigned char *encrypted_username = NULL;
    size_t encrypted_username_len;
    unsigned char *encrypted_domain = NULL;
    size_t encrypted_domain_len;
    unsigned char *encrypted_password = NULL;
    size_t encrypted_password_len;

    char decrypted_username[256] = {0};
    char decrypted_domain[256] = {0};
    char decrypted_password[256] = {0};
    size_t decrypted_username_len, decrypted_domain_len, decrypted_password_len;

    // Encrypt data
    encrypt_data((const unsigned char *)pwd_key, (const unsigned char *)account_username, strlen(account_username), &encrypted_username, &encrypted_username_len);
    encrypt_data((const unsigned char *)pwd_key, (const unsigned char *)account_domain, strlen(account_domain), &encrypted_domain, &encrypted_domain_len);
    encrypt_data((const unsigned char *)img_key, (const unsigned char *)account_password, strlen(account_password), &encrypted_password, &encrypted_password_len);

    // Decrypt data
    decrypt_data((const unsigned char *)pwd_key, encrypted_username, encrypted_username_len, (unsigned char *)decrypted_username, &decrypted_username_len);
    decrypt_data((const unsigned char *)pwd_key, encrypted_domain, encrypted_domain_len, (unsigned char *)decrypted_domain, &decrypted_domain_len);
    decrypt_data((const unsigned char *)img_key, encrypted_password, encrypted_password_len, (unsigned char *)decrypted_password, &decrypted_password_len);

    // Output results for debugging
    printf("Decrypted Username: %s\n", decrypted_username);
    printf("Decrypted Domain: %s\n", decrypted_domain);
    printf("Decrypted Password: %s\n", decrypted_password);

    // Free allocated memory
    free(encrypted_username);
    free(encrypted_domain);
    free(encrypted_password);
}

// void test_encrypt_decrypt_data_from_image(const char *pwd_key, const char *img_key, const char *input_image, char *output_image){
    // const char *account_username = "test_username";
    // const char *account_domain = "test_domain.com";
    // const char *account_password = "ThatBrutalXXNinja280901!";

    // char decrypted_username[256] = {0};
    // char decrypted_domain[256] = {0};
    // char decrypted_password[256] = {0};

//     encrypt_credentials_into_image(pwd_key, img_key, account_username, account_domain, account_password, input_image, output_image);
//     decrypt_credentials_from_image(pwd_key, img_key, output_image, decrypted_username, decrypted_domain, decrypted_password);

//     // // Print results for manual verification
//     // printf("Decrypted_username: %s\n", decrypted_username);
//     // printf("Decrypted_domain: %s\n", decrypted_domain);
//     // printf("Decrypted_password: %s\n", decrypted_password);

//     // Add checks to automatically verify correctness
//     if (strcmp(account_username, decrypted_username) != 0) {
//         printf("Error: Decrypted username does not match the original!\n");
//     } else {
//         printf("Success: Decrypted username matches the original.\n");
//     }

//     if (strcmp(account_domain, decrypted_domain) != 0) {
//         printf("Error: Decrypted domain does not match the original!\n");
//     } else {
//         printf("Success: Decrypted domain matches the original.\n");
//     }

//     if (strcmp(account_password, decrypted_password) != 0) {
//         printf("Error: Decrypted password does not match the original!\n");
//     } else {
//         printf("Success: Decrypted password matches the original.\n");
//     }
// }
