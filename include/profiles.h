#ifndef PROFILES_H
#define PROFILES_H

#include <sodium.h>

#define MAX_USER_NAME_LEN 50
#define MAX_USER_EMAIL_LEN 50
#define MAX_PROFILE_IMAGE_PATH_LEN 256
#define MAX_MASTER_IMAGE_PATH_LEN 256
#define CRYPTO_KEY_LEN 32

// User Profile Struct
typedef struct{
    char user_ID[7]; // identifier for user
    char user_Name[MAX_USER_NAME_LEN];
    char user_Email[MAX_USER_EMAIL_LEN];
    char user_Master_password[crypto_pwhash_STRBYTES]; // hashed version of master password
    char user_Profile_image_path[MAX_PROFILE_IMAGE_PATH_LEN];
    char user_Master_password_image_path[MAX_MASTER_IMAGE_PATH_LEN]; // field for master image path (image that acts as master password)
}Profile;

/* PROFILE MANAGERMENT */
int create_profile(Profile *profile, char *id, const char *name, const char *email, const char*master_password, const char*profile_image_path, const char*master_password_image_path);
void display_profile(Profile *profile);
int update_profile_info(Profile *profile, const char *name, const char *email, const char *profile_image_path);
int delete_profile(Profile *profile);

/* PASSWORD AND MASTER IMAGE MANAGEMENT */
void forgot_master_password(Profile *profile);
void update_master_password(Profile *profile, const char *new_master_password);
void update_master_image(Profile *profile, const char *new_master_image_path);

#endif 