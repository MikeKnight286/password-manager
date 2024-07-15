#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include "utils.h"
#include "test_utils.h"

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

void test_isValidImage(const char *image_path){
    char output_path[256];

    printf("Testing isValidImage function...\n");
    if(isValidImage(image_path, output_path)){
        printf("The file '%s' is a valid image. Output path: '%s'\n", image_path, output_path);
    } else {
        printf("The file '%s' is not a valid image.\n", image_path);
    }
}