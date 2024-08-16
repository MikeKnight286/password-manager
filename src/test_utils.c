#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
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

// Function to generate simple test data
void generate_simple_data(unsigned char **test_data, size_t *test_data_len) {
    // Seed the random number generator
    srand(time(NULL));

    // Define the length of the test data
    *test_data_len = 100; // For example, 100 bytes of data

    // Allocate memory for the test data
    *test_data = (unsigned char *)malloc(*test_data_len * sizeof(unsigned char));

    // Generate random data
    for (size_t i = 0; i < *test_data_len; i++) {
        (*test_data)[i] = rand() % 256; // Random byte between 0 and 255
    }
}

void test_encrypt_decrypt_data(const char *pwd_key, const char *img_key) {
    const char *account_username = "test_username";
    const char *account_domain = "test_domain.com";
    const char *account_password = "ThatBrutalXXNinja280901!";

    EncryptedPart parts[3] = {0};  // username, domain, password

    // Encrypt each part
    if (!encrypt_data((const unsigned char *)pwd_key, (const unsigned char *)account_username, strlen(account_username), &parts[0].data, &parts[0].length) ||
        !encrypt_data((const unsigned char *)pwd_key, (const unsigned char *)account_domain, strlen(account_domain), &parts[1].data, &parts[1].length) ||
        !encrypt_data((const unsigned char *)img_key, (const unsigned char *)account_password, strlen(account_password), &parts[2].data, &parts[2].length)) {
        fprintf(stderr, "Encryption failed.\n");
        goto cleanup;
    }

    // Print encrypted lengths for debugging
    printf("Encrypted username length: %zu\n", parts[0].length);
    printf("Encrypted domain length: %zu\n", parts[1].length);
    printf("Encrypted password length: %zu\n", parts[2].length);

    // Decrypt each part
    char decrypted_username[256] = {0};
    char decrypted_domain[256] = {0};
    char decrypted_password[256] = {0};
    size_t decrypted_lengths[3] = {0};

    if (!decrypt_data((const unsigned char *)pwd_key, parts[0].data, parts[0].length, (unsigned char *)decrypted_username, &decrypted_lengths[0]) ||
        !decrypt_data((const unsigned char *)pwd_key, parts[1].data, parts[1].length, (unsigned char *)decrypted_domain, &decrypted_lengths[1]) ||
        !decrypt_data((const unsigned char *)img_key, parts[2].data, parts[2].length, (unsigned char *)decrypted_password, &decrypted_lengths[2])) {
        fprintf(stderr, "Decryption failed.\n");
        goto cleanup;
    }

    // Null-terminate the decrypted strings
    decrypted_username[decrypted_lengths[0]] = '\0';
    decrypted_domain[decrypted_lengths[1]] = '\0';
    decrypted_password[decrypted_lengths[2]] = '\0';

    // Output results for debugging
    printf("Decrypted Username: %s\n", decrypted_username);
    printf("Decrypted Domain: %s\n", decrypted_domain);
    printf("Decrypted Password: %s\n", decrypted_password);

    // Verify decrypted data matches original
    if (strcmp(account_username, decrypted_username) == 0 &&
        strcmp(account_domain, decrypted_domain) == 0 &&
        strcmp(account_password, decrypted_password) == 0) {
        printf("Test passed: All data encrypted and decrypted successfully.\n");
    } else {
        fprintf(stderr, "Test failed: Decrypted data does not match original.\n");
    }

cleanup:
    // Free allocated memory
    for (int i = 0; i < 3; i++) {
        if (parts[i].data) {
            sodium_memzero(parts[i].data, parts[i].length);
            free(parts[i].data);
        }
    }
}

// Utility function to embed and extract data for testing
void test_embed_extract_data_from_image() {
    const char *input_image_path = "plaintext_image.png";
    const char *output_image_path = "ciphertext_image.png";

    // Generate random test data
    unsigned char *test_data, *extracted_data;
    size_t test_data_len, extracted_data_len;
    generate_simple_data(&test_data, &test_data_len);

    printf("Test_data_len: %zu\n", test_data_len);

    // Embed the data into an image
    if(!embed_data_into_image(input_image_path, output_image_path, test_data, test_data_len)){
        fprintf(stderr, "Failed to embed data\n");
        return;
    };
    
    // Extract the data from the image
    if(!extract_data_from_image(output_image_path, &extracted_data, &extracted_data_len)){
        fprintf(stderr, "Failed to extract data\n");
        return;
    };

    // Compare the original and extracted data
    if (test_data_len != extracted_data_len) {
        printf("Test failed: Data lengths differ.\n");
    } else if (memcmp(test_data, extracted_data, test_data_len) == 0) {
        printf("Test passed: Data extracted matches the original.\n");
    } else {
        printf("Test failed: Extracted data does not match the original.\n");
    }

    // Clean up
    free(test_data);
    free(extracted_data);
}

void test_encrypt_decrypt_data_from_image(const char *pwd_key, const char *img_key, const char *input_image, char *output_image) {
    // Test credentials
    const char *account_username = "test_username_for_domain";
    const char *account_domain = "test_domain.com";
    const char *account_password = "ThatBrutalXXNinja280901!";

    unsigned char *encrypted_username, *encrypted_domain, *encrypted_password;
    size_t encrypted_username_len, encrypted_domain_len, encrypted_password_len;

    // Encrypt data
    if (!encrypt_data((const unsigned char *)pwd_key, (const unsigned char *)account_username, strlen(account_username), &encrypted_username, &encrypted_username_len) ||
        !encrypt_data((const unsigned char *)pwd_key, (const unsigned char *)account_domain, strlen(account_domain), &encrypted_domain, &encrypted_domain_len) ||
        !encrypt_data((const unsigned char *)img_key, (const unsigned char *)account_password, strlen(account_password), &encrypted_password, &encrypted_password_len)) {
        printf("Encryption failed\n");
        return;
    }

    // Combine encrypted data
    size_t total_data_len = encrypted_username_len + encrypted_domain_len + encrypted_password_len;
    unsigned char *combined_data = malloc(total_data_len);
    if (!combined_data) {
        printf("Failed to allocate memory for combined data\n");
        return;
    }
    memcpy(combined_data, encrypted_username, encrypted_username_len);
    memcpy(combined_data + encrypted_username_len, encrypted_domain, encrypted_domain_len);
    memcpy(combined_data + encrypted_username_len + encrypted_domain_len, encrypted_password, encrypted_password_len);

    // Embed combined data into an image
    if (!embed_data_into_image(input_image, output_image, combined_data, total_data_len)) {
        printf("Failed to embed data into image\n");
        free(combined_data);
        return;
    }
    free(combined_data);

    // Extract data from image
    unsigned char *extracted_data;
    size_t extracted_data_len;
    if (!extract_data_from_image(output_image, &extracted_data, &extracted_data_len)) {
        printf("Failed to extract data from image\n");
        return;
    }

    // Decrypt extracted data
    unsigned char decrypted_username[1024], decrypted_domain[1024], decrypted_password[1024];
    size_t decrypted_username_len, decrypted_domain_len, decrypted_password_len;
    if (!decrypt_data((const unsigned char *)pwd_key, extracted_data, encrypted_username_len, decrypted_username, &decrypted_username_len) ||
        !decrypt_data((const unsigned char *)pwd_key, extracted_data + encrypted_username_len, encrypted_domain_len, decrypted_domain, &decrypted_domain_len) ||
        !decrypt_data((const unsigned char *)img_key, extracted_data + encrypted_username_len + encrypted_domain_len, encrypted_password_len, decrypted_password, &decrypted_password_len)) {
        printf("Decryption failed\n");
        free(extracted_data);
        return;
    }
    decrypted_username[decrypted_username_len] = '\0';
    decrypted_domain[decrypted_domain_len] = '\0';
    decrypted_password[decrypted_password_len] = '\0';

    // Output decrypted data
    printf("Decrypted Username: %s\n", decrypted_username);
    printf("Decrypted Domain: %s\n", decrypted_domain);
    printf("Decrypted Password: %s\n", decrypted_password);

    free(extracted_data);
}

// Test generating random password given username and domain
void test_generate_random_password(){
    const char *account_username = "test_username_for_domain";
    const char *account_domain = "test_domain.com";

    char generated_password[256];

    generate_random_password(account_username, account_domain, generated_password);
    printf("Generated password: %s\n", generated_password);

}