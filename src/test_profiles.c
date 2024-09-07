#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "utils.h"
#include "profiles.h"
#include "test_profiles.h"
#include "logger.h"
#include "profile_errors.h"

// Test for create_profile function
void test_create_profile() {
    Profile profile;
    int result = create_profile(&profile, NULL, "John Doe", "john.doe@example.com", "AmberTreePunchesCars00#4", "test.png", "test.png");

    assert(result == SUCCESS);
    assert(strcmp(profile.user_Name, "John Doe") == 0);
    assert(strcmp(profile.user_Email, "john.doe@example.com") == 0);
    assert(strcmp(profile.user_Profile_image_path, "test.png") == 0);
    assert(strcmp(profile.user_Master_password_image_path, "test.png") == 0);
    
    printf("test_create_profile passed.\n");

    // Test error cases
    result = create_profile(NULL, NULL, "John Doe", "john.doe@example.com", "AmberTreePunchesCars00#4", "test.png", "test.png");
    assert(result == ERROR_NULL_PARAMETER);

    result = create_profile(&profile, NULL, "John Doe", "invalid_email", "AmberTreePunchesCars00#4", "test.png", "test.png");
    assert(result == ERROR_INVALID_INPUT);

    result = create_profile(&profile, NULL, "John Doe", "john.doe@example.com", "weak", "test.png", "test.png");
    assert(result == ERROR_WEAK_PASSWORD);

    printf("test_create_profile error cases passed.\n");
}

// Test for display_profile function
void test_display_profile() {
    Profile profile;
    generate_random_id(profile.user_ID, sizeof(profile.user_ID));
    strncpy(profile.user_Name, "John Doe", sizeof(profile.user_Name) - 1);
    profile.user_Name[sizeof(profile.user_Name) - 1] = '\0';
    strncpy(profile.user_Email, "john.doe@example.com", sizeof(profile.user_Email) - 1);
    profile.user_Email[sizeof(profile.user_Email) - 1] = '\0';
    strncpy(profile.user_Profile_image_path, "test.png", sizeof(profile.user_Profile_image_path) - 1);
    profile.user_Profile_image_path[sizeof(profile.user_Profile_image_path) - 1] = '\0';
    strncpy(profile.user_Master_password_image_path, "test.png", sizeof(profile.user_Master_password_image_path) - 1);
    profile.user_Master_password_image_path[sizeof(profile.user_Master_password_image_path) - 1] = '\0';

    // Redirect stdout to a buffer for validation
    FILE *temp = freopen("test_display_profile_output.txt", "w", stdout);
    if (temp == NULL) {
        LOG_ERROR("Failed to redirect stdout for testing.");
        return;
    }

    display_profile(&profile, 2);  // Display with high security level
    fflush(stdout);
    freopen("/dev/tty", "w", stdout);

    // Read the output and validate it
    FILE *output = fopen("test_display_profile_output.txt", "r");
    if (output == NULL) {
        LOG_ERROR("Failed to open test output file.");
        return;
    }

    char buffer[1024] = {0};
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, output);
    fclose(output);

    if (bytes_read == 0) {
        LOG_ERROR("Failed to read test output.");
        return;
    }

    // Validate the expected output
    assert(strstr(buffer, "User ID: ") != NULL);
    assert(strstr(buffer, profile.user_ID) != NULL);
    assert(strstr(buffer, "Name: John Doe") != NULL);
    assert(strstr(buffer, "Email: john.doe@example.com") != NULL);
    assert(strstr(buffer, "Profile Image Path: test.png") != NULL);
    assert(strstr(buffer, "Master Password Image Path: test.png") != NULL);
    assert(strstr(buffer, "[SECURE]") != NULL);

    printf("test_display_profile passed.\n");

    // Test with lower security level
    temp = freopen("test_display_profile_output_low_security.txt", "w", stdout);
    if (temp == NULL) {
        LOG_ERROR("Failed to redirect stdout for low security testing.");
        return;
    }

    display_profile(&profile, 1);  // Display with low security level
    fflush(stdout);
    freopen("/dev/tty", "w", stdout);

    output = fopen("test_display_profile_output_low_security.txt", "r");
    if (output == NULL) {
        LOG_ERROR("Failed to open low security test output file.");
        return;
    }

    memset(buffer, 0, sizeof(buffer));
    bytes_read = fread(buffer, 1, sizeof(buffer) - 1, output);
    fclose(output);

    if (bytes_read == 0) {
        LOG_ERROR("Failed to read low security test output.");
        return;
    }

    // Validate the expected output for low security level
    assert(strstr(buffer, "User ID: ") != NULL);
    assert(strstr(buffer, profile.user_ID) != NULL);
    assert(strstr(buffer, "Name: John Doe") != NULL);
    assert(strstr(buffer, "Email: john.doe@example.com") != NULL);
    assert(strstr(buffer, "Profile Image Path: ") == NULL);  // Should not be displayed in low security
    assert(strstr(buffer, "Master Password Image Path: ") == NULL);  // Should not be displayed in low security
    assert(strstr(buffer, "[SECURE]") != NULL);

    printf("test_display_profile with low security level passed.\n");
}