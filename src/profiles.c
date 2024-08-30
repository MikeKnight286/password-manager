#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include "profiles.h"
#include "utils.h"
#include "logger.h"  

#define SUCCESS 0
#define ERROR_NULL_PARAMETER 1
#define ERROR_INPUT_TOO_LONG 2
#define ERROR_INVALID_INPUT 3
#define ERROR_WEAK_PASSWORD 4

/* PROFILE MANAGEMENT */
int create_profile(Profile *profile, char *id, const char *name, const char *email, const char*master_password, const char*profile_image_path, const char*master_password_image_path){
    // Error handling 
    if (!profile || !name || !email || !master_password || !profile_image_path || !master_password_image_path) {
        log_error("One or more required parameters are missing.");
        return ERROR_NULL_PARAMETER;
    }

    if (strlen(name) >= MAX_USER_NAME_LEN || strlen(email) >= MAX_USER_EMAIL_LEN) {
        log_error("Name or email exceeds maximum length.");
        return ERROR_INPUT_TOO_LONG;
    }

    if (!isValidName(name)) {
        log_error("Invalid name provided: %s", name);
        return ERROR_INVALID_INPUT;
    }

    if (!isValidEmail(email)) {
        log_error("Invalid email address provided: %s", email);
        return ERROR_INVALID_INPUT;
    }
    
    if (!isStrongPassword(master_password)) {
        log_error("Master password not strong enough.");
        return ERROR_WEAK_PASSWORD;
    }

    // Generate random user ID
    generate_random_id(profile->user_ID, sizeof(profile->user_ID));

    // Hash the master password
    string_to_argon2hash(master_password, profile->user_Master_password);

    // Generate image fingerprint from master image
    char image_fingerprint[128];
    generate_fingerprint_from_image(master_password_image_path, profile->user_ID, email, image_fingerprint);

    // Generate cryptographic keys from image fingerprint and master password
    char key_from_password[CRYPTO_KEY_LEN], key_from_image[CRYPTO_KEY_LEN];
    generate_key_from_password(master_password, key_from_password, sizeof(key_from_password));
    generate_key_from_image_fingerprint(image_fingerprint, key_from_image, sizeof(key_from_image));

    // Store the rest of the data
    strncpy(profile->user_Name, name, MAX_USER_NAME_LEN - 1);
    profile->user_Name[MAX_USER_NAME_LEN - 1] = '\0';  // Ensure null-termination
    strncpy(profile->user_Email, email, MAX_USER_EMAIL_LEN - 1);
    profile->user_Email[MAX_USER_EMAIL_LEN - 1] = '\0';
    strncpy(profile->user_Profile_image_path, profile_image_path, MAX_PROFILE_IMAGE_PATH_LEN - 1);
    profile->user_Profile_image_path[MAX_PROFILE_IMAGE_PATH_LEN - 1] = '\0';
    strncpy(profile->user_Master_password_image_path, master_password_image_path, MAX_MASTER_IMAGE_PATH_LEN - 1);
    profile->user_Master_password_image_path[MAX_MASTER_IMAGE_PATH_LEN - 1] = '\0';

    log_info("Profile created successfully with ID %s.", profile->user_ID); 
    return SUCCESS;
}

void display_profile(Profile *profile, int security_level) {
    if (!profile) {
        log_error("No profile data to display.");
        return;
    }

    printf("===============================\n");
    printf("Profile Details:\n");
    printf("===============================\n");
    printf("User ID: %s\n", profile->user_ID);
    printf("Name: %s\n", profile->user_Name);
    printf("Email: %s\n", profile->user_Email);
    
    if (security_level > 1) {
        printf("Profile Image Path: %s\n", profile->user_Profile_image_path);
        printf("Master Password Image Path: %s\n", profile->user_Master_password_image_path);
    }

    // For security reasons, we do not print the master password or the keys
    printf("Master Password: [SECURE]\n");
    printf("Cryptographic Keys: [SECURE]\n");
    printf("===============================\n");

    log_info("Profile displayed for user %s", profile->user_ID);
}

void update_profile_info(Profile *profile, char *id, const char *name, const char *email, const char *profile_image_path) {
    // Error handling
    if (!profile || !id || !name || !email || !profile_image_path) {
        printf("Missing input parameters.\n");
        return;
    }

    // Check if the provided ID matches the profile's ID
    if (strcmp(profile->user_ID, id) != 0) {
        printf("Profile ID does not exist or does not match.\n");
        return;
    }

    // Update the name, email, and profile image path
    if (strlen(name) >= sizeof(profile->user_Name)) {
        printf("Name too long.\n");
        return;
    }

    if (strlen(email) >= sizeof(profile->user_Email)) {
        printf("Email too long.\n");
        return;
    }

    strncpy(profile->user_Name, name, MAX_USER_NAME_LEN);
    strncpy(profile->user_Email, email, MAX_USER_EMAIL_LEN);
    strncpy(profile->user_Profile_image_path, profile_image_path, MAX_PROFILE_IMAGE_PATH_LEN);

    printf("Profile information updated successfully.\n");
}

void delete_profile(Profile *profile) {
    if (!profile) {
        printf("Profile does not exist.\n");
        return;
    }

    // Clear the profile data
    memset(profile->user_ID, 0, sizeof(profile->user_ID));
    memset(profile->user_Name, 0, sizeof(profile->user_Name));
    memset(profile->user_Email, 0, sizeof(profile->user_Email));
    memset(profile->user_Master_password, 0, sizeof(profile->user_Master_password));
    memset(profile->user_Profile_image_path, 0, sizeof(profile->user_Profile_image_path));
    memset(profile->user_Master_password_image_path, 0, sizeof(profile->user_Master_password_image_path));

    printf("Profile deleted successfully.\n");
}


/* PASSWORD AND MASTER IMAGE MANAGEMENT */
void forgot_master_password(Profile *profile){

}   

void update_master_password(Profile *profile, const char *new_master_password){

}

void update_master_image(Profile *profile, const char *new_master_image_path){

}





