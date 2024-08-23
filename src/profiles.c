#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include "profiles.h"
#include "utils.h"

/* PROFILE MANAGEMENT */
void create_profile(Profile *profile, char *id, const char *name, const char *email, const char*master_password, const char*profile_image_path, const char*master_password_image_path){
    // Error handling 
    if (!profile) {
    printf("Error: 'profile' parameter is missing.\n");
    return;
    }
    if (!name) {
        printf("Error: 'name' parameter is missing.\n");
        return;
    }
    if (!email) {
        printf("Error: 'email' parameter is missing.\n");
        return;
    }
    if (!master_password) {
        printf("Error: 'master_password' parameter is missing.\n");
        return;
    }
    if (!profile_image_path) {
        printf("Error: 'profile_image_path' parameter is missing.\n");
        return;
    }
    if (!master_password_image_path) {
        printf("Error: 'master_password_image_path' parameter is missing.\n");
        return;
    }

    if(strlen(name) >= sizeof(profile->user_Name) || strlen(email) >= sizeof(profile->user_Email)){
        printf("Name or email too long.\n");
        return;
    }

    if(!isValidName(name)){
        printf("Invalid name: %s\n", name);
        return;
    }

    if(!isValidEmail(email)){
        printf("Invalid email address: %s\n", email);
        return;
    }
    
    if(!isStrongPassword(master_password)){
        printf("Master password not strong enough.\n", master_password);
        return;
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
    strncpy(profile->user_Name, name, MAX_USER_NAME_LEN);
    strncpy(profile->user_Email, email, MAX_USER_EMAIL_LEN);
    strncpy(profile->user_Profile_image_path, profile_image_path, MAX_PROFILE_IMAGE_PATH_LEN);
    strncpy(profile->user_Master_password_image_path, master_password_image_path, MAX_MASTER_IMAGE_PATH_LEN);

    printf("Profile created successfully with ID %s.\n", profile->user_ID); 
}

void display_profile(Profile *profile){
    if (!profile) {
        printf("No profile data to display.\n");
        return;
    }

    printf("Profile Details:\n");
    printf("User ID: %s\n", profile->user_ID);
    printf("Name: %s\n", profile->user_Name);
    printf("Email: %s\n", profile->user_Email);
    printf("Profile Image Path: %s\n", profile->user_Profile_image_path);
    printf("Master Password Image Path: %s\n", profile->user_Master_password_image_path);

    // For security reasons, we do not print the master password or the keys
    printf("Master Password: [SECURE]\n");
    printf("Cryptographic Key from Password: [SECURE]\n");
    printf("Cryptographic Key from Image: [SECURE]\n");
}

void update_profile_info(Profile *profile, const char *name, const char *email, const char *profile_image_path){

}

void delete_profile(Profile *profile){

}


/* PASSWORD AND MASTER IMAGE MANAGEMENT */
void forgot_master_password(Profile *profile){

}   

void update_master_password(Profile *profile, const char *new_master_password){

}

void update_master_image(Profile *profile, const char *new_master_image_path){

}





