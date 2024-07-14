#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <sodium.h>
#include <math.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include "zxcvbn.h"
#include "utils.h"

#define SINGLE_GUESS 0.010
#define NUM_ATTACKERS 1000
#define SECONDS_PER_GUESS (SINGLE_GUESS / NUM_ATTACKERS)

// Check if string contains invalid chars
bool contains_invalid_chars(const char *str, const char *invalid_chars_email){
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

// Check password's strength

double entropy_to_crack_time(double entropy) {
    return (0.5 * pow(2, entropy)) * SECONDS_PER_GUESS;
}

const char *display_crack_time(double seconds) {
    static char buffer[50]; // buffer to hold the crack time string
    if (seconds < 60) {
        snprintf(buffer, sizeof(buffer), "instant");
    } else if (seconds < 3600) {
        snprintf(buffer, sizeof(buffer), "%.0f minutes", ceil(seconds / 60));
    } else if (seconds < 86400) {
        snprintf(buffer, sizeof(buffer), "%.0f hours", ceil(seconds / 3600));
    } else if (seconds < 2678400) {
        snprintf(buffer, sizeof(buffer), "%.0f days", ceil(seconds / 86400));
    } else if (seconds < 32140800) {
        snprintf(buffer, sizeof(buffer), "%.0f months", ceil(seconds / 2678400));
    } else if (seconds < 3214080000) {
        snprintf(buffer, sizeof(buffer), "%.0f years", ceil(seconds / 32140800));
    } else {
        snprintf(buffer, sizeof(buffer), "centuries");
    }
    return buffer;
}

bool isStrongPassword(const char *password) {
    ZxcMatch_t *matches = NULL;
    double entropy = ZxcvbnMatch(password, NULL, &matches);
    double crack_time = entropy_to_crack_time(entropy);
    const char *crack_time_display = display_crack_time(crack_time);
    bool is_strong = true;
    bool has_feedback = false;
    bool dictionary_feedback_given = false;
    bool pattern_feedback_given = false;

    // Feedback based on entropy thresholds
    const double entropy_threshold_poor = 28;
    const double entropy_threshold_weak = 35;
    const double entropy_threshold_medium = 60; // this password is good enough I guess
    const double entropy_threshold_strong = 127;

    if (entropy < entropy_threshold_poor) {
        is_strong = false;
        has_feedback = true;
    } else if (entropy < entropy_threshold_weak) {
        is_strong = false;
        has_feedback = true;
    } else if (entropy < entropy_threshold_medium) {
        is_strong = true;
        has_feedback = true;
    } else if (entropy < entropy_threshold_strong) {
        is_strong = true;
        has_feedback = true;
    } else {
        is_strong = true;
        has_feedback = true;
    }

    // Feedback based on matches and characteristics
    bool has_uppercase = false, has_lowercase = false, has_digit = false, has_special = false; 
    int length = strlen(password);
    for (int i = 0; i < length; i++) {
        if (password[i] >= 'A' && password[i] <= 'Z') has_uppercase = true;
        else if (password[i] >= 'a' && password[i] <= 'z') has_lowercase = true;
        else if (password[i] >= '0' && password[i] <= '9') has_digit = true;
        else if (strchr("!@#$%%^&*()", password[i])) has_special = true;
    }

    if (!has_uppercase || !has_lowercase || !has_digit || !has_special || length < 12) {
        is_strong = false;
        has_feedback = true;
    }

    // Feedback based on common passwords or patterns
    ZxcMatch_t *match = matches;
    while (match != NULL) {
        if (!dictionary_feedback_given && (match->Type == DICTIONARY_MATCH || match->Type == DICT_LEET_MATCH)) {
            printf("Password contains dictionary words or common patterns. Consider making it less predictable.\n");
            has_feedback = true;
            dictionary_feedback_given = true;
        }
        if (!pattern_feedback_given && (match->Type == REPEATS_MATCH || match->Type == SEQUENCE_MATCH || match->Type == SPATIAL_MATCH)) {
            printf("Password contains repeated patterns or sequences. Consider using more varied characters.\n");
            has_feedback = true;
            pattern_feedback_given = true;
        }
        match = match->Next;
    }

    // Print detailed feedback for the password
    if (has_feedback) {
        printf("Estimated crack time: %s\n", crack_time_display);
        if (entropy < entropy_threshold_poor) {
            printf("Poor password.\n");
        } else if (entropy < entropy_threshold_weak) {
            printf("Still a weak password.\n");
        } else if (entropy < entropy_threshold_medium) {
            printf("Reasonable for a password. Could be a bit better.\n");
        } else if (entropy < entropy_threshold_strong) {
            printf("Good password.\n");
        } else {
            printf("Excellent password.\n");
        }

        if (!has_uppercase) {
            printf("Please add at least one uppercase letter.\n");
        }
        if (!has_lowercase) {
            printf("Please add at least one lowercase letter.\n");
        }
        if (!has_digit) {
            printf("Please add at least one number.\n");
        }
        if (!has_special) {
            printf("Please add at least one special character (e.g., !@#$%%^&*).\n");
        }
        if (length < 12) {
            printf("Your password is too short. Make it at least 12 characters long.\n");
        }
    }

    // Free the match info
    ZxcvbnFreeInfo(matches);

    return is_strong;
}

// Hashes strings with Argon2
void string_to_argon2hash(const char *input_string, char *hashed_string){
    if (sodium_init() < 0){
        fprintf(stderr, "Failed to initialize libsodium\n");
        return;
    }

    hashed_string[crypto_pwhash_STRBYTES];
    
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
bool verify_argon2hash(const char *input_string, const char *hashed_string){
    if (sodium_init() <0){
        fprintf(stderr, "Failed to initialize libsodium\n");
        return false;
    }

    if (crypto_pwhash_str_verify(hashed_string, input_string, strlen(input_string)) == 0){
        return true;
    }

    return false;
}

// Convert JPEG to PNG for lossless compression 
bool convertJPEGtoPNG(const char *jpeg_path, const char *png_path){
    // Initialize SDL2_image for JPG and PNG 
    if(IMG_Init(IMG_INIT_JPG | IMG_INIT_PNG) == 0){
        fprintf(stderr, "Failed to initialize SDL2_image: %s\n", IMG_GetError());
    }
    
    // Load the JPEG image for debugging
    SDL_Surface *image = IMG_Load(jpeg_path);
    if(image == NULL){
        fprintf(stderr, "Failed to load JPEG image: %s\n", IMG_GetError());
        IMG_Quit();
        return false;
    }

    // Save the image as PNG
    if (IMG_SavePNG(image, png_path) != 0){
        fprintf(stderr, "Failed to save image as PNG: %s\n", IMG_GetError());
        SDL_FreeSurface(image);
        IMG_Quit();
        return false;
    }

    SDL_FreeSurface(image);
    IMG_Quit();

    return true;
}


// Check if the uploaded image file has correct extension
bool hasValidImageExtension(const char *image_path){
    const char *valid_extensions[] = {".png", ".tiff", ".tif", ".jpg", ".jpeg"};
    const int num_valid_extensions = sizeof(valid_extensions) / sizeof(valid_extensions[0]);

    const char *dot = strrchr(image_path, '.');
    if(!dot || dot == image_path) return false;

    for (int i=0; i<num_valid_extensions; i++){
        if(strcasecmp(dot, valid_extensions[i]) == 0){
            return true;
        }
    }
    return false;
}


// Check if the upload file is an image
bool isValidImage(const char *image_path){
    if(!hasValidImageExtension){
        return false;
    }

    const char *dot = strchr(image_path, '.');
    if(strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0){
        char png_path[256];
        strncpy(png_path, image_path, strlen(image_path) - strlen(dot));
        strncat(png_path, ".png", 5);

        if (!convertJPEGtoPNG(image_path, png_path)) {
            return false;
        }

        image_path = png_path;
    }

    if(IMG_Init(IMG_INIT_PNG | IMG_INIT_TIF | IMG_INIT_JPG ) == 0){
        fprintf(stderr, "Failed to initialize SDL2_image: %s\n", IMG_GetError());
        return false;
    }

    SDL_Surface *image = IMG_Load(image_path);
    if(image == NULL){
        IMG_Quit();
        return false;
    }

    SDL_FreeSurface(image);
    IMG_Quit();

    return true;
}

