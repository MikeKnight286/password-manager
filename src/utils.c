#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
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