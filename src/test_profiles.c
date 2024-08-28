#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "utils.h"
#include "profiles.h"
#include "test_profiles.h"

// Test for create_profile function
void test_create_profile() {
    Profile profile;
    create_profile(&profile, NULL, "John Doe", "john.doe@example.com", "AmberTreePunchesCars00#4", "test.png", "test.png");

    // Validate the generated profile data
    assert(strcmp(profile.user_Name, "John Doe") == 0);
    printf("Expected: John Doe, Actual: %s\n", profile.user_Name);
    assert(strcmp(profile.user_Email, "john.doe@example.com") == 0);
    assert(strcmp(profile.user_Profile_image_path, "test.png") == 0);
    assert(strcmp(profile.user_Master_password_image_path, "test.png") == 0);
    
    printf("test_create_profile passed.\n");
}

// Test for display_profile function
void test_display_profile() {
    Profile profile;
    generate_random_id(profile.user_ID, sizeof(profile.user_ID));
    strncpy(profile.user_Name, "John Doe", sizeof(profile.user_Name));
    strncpy(profile.user_Email, "john.doe@example.com", sizeof(profile.user_Email));
    strncpy(profile.user_Profile_image_path, "test.png", sizeof(profile.user_Profile_image_path));
    strncpy(profile.user_Master_password_image_path, "test.png", sizeof(profile.user_Master_password_image_path));

    // Redirect stdout to a buffer for validation
    freopen("test_display_profile_output.txt", "w", stdout);
    display_profile(&profile);
    freopen("/dev/tty", "w", stdout);

    // Read the output and validate it
    FILE *output = fopen("output.txt", "r");
    char buffer[1024];
    fread(buffer, sizeof(char), 1024, output);
    fclose(output);

    // Validate the expected output
    assert(strstr(buffer, "User ID: ") != NULL); // Ensure User ID is displayed
    assert(strstr(buffer, profile.user_ID) != NULL); // Ensure the correct User ID is displayed
    assert(strstr(buffer, "Name: John Doe") != NULL);
    assert(strstr(buffer, "Email: john.doe@example.com") != NULL);
    assert(strstr(buffer, "Profile Image Path: test.png") != NULL);
    assert(strstr(buffer, "Master Password Image Path: test.png") != NULL);
    assert(strstr(buffer, "[SECURE]") != NULL); // Ensure secure fields are displayed as [SECURE]

    printf("test_display_profile passed.\n");
}