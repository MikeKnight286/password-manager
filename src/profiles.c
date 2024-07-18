#include <stdio.h>
#include <string.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include "profiles.h"
#include "utils.h"

/* PROFILE MANAGEMENT */
void create_profile(Profile *profile, int id, const char *name, const char *email, const char*master_password, const char*profile_image_path, const char*master_password_image_path){
    // Error handling 
    if(!isValidEmail(email)){
        printf("Invalid email address: %s\n", email);
        return;
    }
    
    if(!isStrongPassword(master_password)){
        printf("Master password ""%s"" not strong enough.\n", master_password);
        return;
    }

    static char profile_output_image[256]; // char array to store profile image output file path
    if(!isValidImage(profile_image_path, profile_output_image)){
        printf("Image \"%s\" is not valid.\n", profile_image_path);
        return;
    }
    
    static char master_image_output_path[256]; // char array to store master image output file path
    if(!isValidImage(master_password_image_path, master_image_output_path)){
        printf("Image \"%s\" is not valid.\n", profile_image_path);
        return;
    }

}

void display_profile(Profile *profile){

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





