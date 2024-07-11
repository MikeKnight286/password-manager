#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include "zxcvbn-c/zxcvbn.h"
#include "utils.h"

// Check if string contains invalid chars
bool contains_invalid_chars(const char *str,const char *invalid_chars_email){
    while (*str){
        if(strchr(invalid_chars_email, *str)){
            return true;
        }
        str++;
    }
    return false;
}

// Check if email is valid
bool isValidEmail(const char *email) {
    const char invalid_chars_email[] = "/:;<>,[] \t\n\r";
    const char *at = strchr(email, '@');
    /* If @ not found, @ is the first char in email, another @ found after the first one, or '.' is not found after @ */
    if(!at || at == email || strchr(at+1, '@') || !strchr(at, '.')){
        return false;
    }

    if (contains_invalid_chars(email, invalid_chars_email)){
        return false;
    }

    return true;
}

// Checks if master password is strong enough
bool isStrongPassword(const char *password){
    ZxcMatch_t *matches = NULL;
    double entropy = ZxcvbnMatch(password, NULL, &matches);
    bool is_strong = true;

    // Feedback based on entropy thresholds 
    const double entropy_threshold_weak = 28;
    const double entropy_threshold_medium = 35;
    const double entropy_threshold_strong = 50;

    if (entropy < entropy_threshold_weak){
        printf("Password is weak.\n");
        is_strong = false;
    } else if (entropy < entropy_threshold_medium){
        printf("Password is medium strength.\n");
        is_strong = false;
    } else if (entropy < entropy_threshold_strong){
        printf("Password is almost strong.\n");
        is_strong = false;
    } else {
        printf("Password is strong.\n");
    }

    // Feedback based on matches and characteristics
    bool has_uppercase = false, has_lowercase = false, has_digit = false, has_special = false; 
    int length = strlen(password);
    for (int i=0; i<length; i++){
        if(password[i] >= 'A' && password[i] <= 'Z') has_uppercase = true;
        else if(password[i] >= 'a' && password[i] <= 'z') has_lowercase = true;
        else if (password[i] >= '0' && password[i] <= '9') has_digit = true;
        else has_special = true;
    }

    if(!has_uppercase){
        printf("Please add at least one uppercase letter.\n");
        is_strong = false;
    }
    if(!has_lowercase){
        printf("Please add at least one lowercase letter.\n");
        is_strong = false;
    }
    if(!has_digit){
        printf("Please add at least one number.\n");
        is_strong = false; 
    }
    if(!has_special){
        printf("Please add at least one special character (e.g., !@#$^&*%%).\n");
        is_strong = false; 
    }
    if (length < 12){
        printf("Your password is too short. Make it at least 12 characters long.\n");
    }

    // Feedback based on common passwords or patterns
    ZxcMatch_t *match = matches;
    while(match !=NULL){
        
    }
}

// Hashes strings with Argon2
void string_to_argon2hash(const char *input_string){
    if (sodium_init() < 0){
        fprintf(stderr, "Failed to initialize libsodium\n");
        return;
    }

    char hashed_string[crypto_pwhash_STRBYTES];

    if(crypto_pwhash_str(
            hashed_string,
            input_string,
            strlen(input_string),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0
    ){
        fprintf(stderr, "Failed to hash the input string\n");
        return;
    } 
}

// Verify password with hash
void verify_argon2hash(const char *input_string, const char *hashed_string){
    if (sodium_init() <0){
        fprintf(stderr, "Failed to initialize libsodium\n");
        return;
    }

    if (crypto_pwhash_str_verify(input_string, hashed_string, strlen(input_string)) == 0){
        return true;
    }

    return false;
}