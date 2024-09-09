#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <sodium.h>
#include <math.h>
#include <time.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <png.h>
#include "zxcvbn.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "logger.h"
#include "utils.h"

#define SINGLE_GUESS 0.010
#define NUM_ATTACKERS 1000
#define SECONDS_PER_GUESS (SINGLE_GUESS / NUM_ATTACKERS)

// Utility function to check if string contains invalid chars
bool contains_invalid_chars(const char *str, const char *invalid_chars){
    while (*str){
        if(strchr(invalid_chars, *str)){
            return true;
        }
        str++;
    }
    return false;
}

// Utility function to check if a string contains at least one alphabetic char
bool contains_alpha(const char *str){
    while(*str){
        if(isalpha((unsigned char) *str)){
            return true;
        }
        str++;
    }
    return false;
}

// Utility function to check if required to convert JPG and TIFF to PNG
bool needsConversionToPNG(const char *input_path) {
    const char *extensions[] = {".jpg", ".jpeg", ".tif", ".tiff"};
    const char *dot = strrchr(input_path, '.');
    if (!dot) return false;  // No extension found

    for (int i = 0; i < sizeof(extensions)/sizeof(extensions[0]); i++) {
        if (strcasecmp(dot, extensions[i]) == 0) return true;
    }

    return false;  // Extension not found in list
}

// Utility function to clean up SDL2_libpng resource
void cleanup_SDL2_libpng(SDL_Surface *image, FILE *fp, png_structp png_ptr, png_infop info_ptr){
    if(info_ptr) png_destroy_info_struct(png_ptr, &info_ptr);
    if(png_ptr) png_destroy_read_struct(&png_ptr, NULL, NULL);
    if(fp) fclose(fp);
    if(image) SDL_FreeSurface(image);
    IMG_Quit();
    SDL_Quit();
}

// Utility function to generate user id
void generate_random_id(char *id, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < size - 1; ++i) {
        int key = randombytes_uniform((uint32_t) strlen(charset));
        id[i] = charset[key];
    }
    id[size - 1] = '\0'; // Null-terminate the string
}

// Initialize SDL2_img for PNG, JPG, TIFF (Call this globally at beginning of application)
void initialize_sdl2_img() {
    static bool is_initialized = false;
    if (!is_initialized) {
        if(SDL_Init(SDL_INIT_VIDEO) < 0) {
            fprintf(stderr, "Cannot initialize SDL: %s\n", SDL_GetError());
            exit(1);
        }
        int img_flags = IMG_INIT_JPG | IMG_INIT_PNG | IMG_INIT_TIF;
        if ((IMG_Init(img_flags) & img_flags) != img_flags) {
            fprintf(stderr, "Failed to load image support: %s\n", SDL_GetError());
            SDL_Quit();
            exit(1);
        }
        is_initialized = true; // Set the flag to prevent future initializations
    }
}

// Utility function to load an image and initialize PNG reading
SDL_Surface *load_PNG_image(const char *input_image, FILE **fp, png_structp *png_ptr, png_infop *info_ptr){
    // Load SDL surface for image
    SDL_Surface *image = IMG_Load(input_image);
    if(!image){
        fprintf(stderr, "Unable to load image: %s\n", SDL_GetError());
        cleanup_SDL2_libpng(image, *fp, *png_ptr, *info_ptr);
    }

    // Initialize libpng structs 
    // Open image file
    *fp = fopen(input_image, "rb");
    if(!*fp){
        cleanup_SDL2_libpng(image, *fp, *png_ptr, *info_ptr);
    }

    // Create png struct for image
    *png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if(!*png_ptr){
        cleanup_SDL2_libpng(image, *fp, *png_ptr, *info_ptr);
    }

    // Metadata struct of PNG image
    *info_ptr = png_create_info_struct(*png_ptr);
    if(!*info_ptr){
        cleanup_SDL2_libpng(image, *fp, *png_ptr, *info_ptr);
    }

    // Error ptr when lib faces error, jump back here
    if(setjmp(png_jmpbuf(*png_ptr))){
        cleanup_SDL2_libpng(image, *fp, *png_ptr, *info_ptr);
    }

    png_init_io(*png_ptr, *fp);
    png_read_info(*png_ptr, *info_ptr);
    return image;
}

// Utility function to convert image to PNG for lossless compression 
bool convertImagetoPNG(const char *input_path, const char *png_path){
    if (!needsConversionToPNG(input_path)) {
        fprintf(stderr, "Unsupported file format.\n");
        return false;
    }

    // Load the image for debugging
    SDL_Surface *image = IMG_Load(input_path);
    if(image == NULL){
        fprintf(stderr, "Failed to load image: %s\n", IMG_GetError());
        cleanup_SDL2_libpng(image, NULL, NULL, NULL);
        return false;
    }

    // Save the image as PNG
    if (IMG_SavePNG(image, png_path) != 0){
        fprintf(stderr, "Failed to save image as PNG: %s\n", IMG_GetError());
        cleanup_SDL2_libpng(image, NULL, NULL, NULL);
        return false;
    }

    cleanup_SDL2_libpng(image, NULL, NULL, NULL);
    return true;
}

// Utility function to calculate SHA-256 hash
bool compute_sha256_hash(const unsigned char *data, size_t data_len, unsigned char *output, unsigned int *output_len) {
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "Failed to create EVP_MD_CTX.\n");
        return false;
    }

    bool success = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1 &&
                   EVP_DigestUpdate(mdctx, data, data_len) == 1 &&
                   EVP_DigestFinal_ex(mdctx, output, output_len) == 1;

    EVP_MD_CTX_free(mdctx);
    return success;
}

// Utility function to combine the hashes
void hash_and_combine(unsigned char *hash1, unsigned int len1, unsigned char *hash2, unsigned int len2, char *final_hash) {
    unsigned int total_length = len1 + len2;
    unsigned char *combined_data = malloc(total_length); // Allocate memory for combined data
    if (!combined_data) {
        fprintf(stderr, "Failed to allocate memory for datastring for hash.\n");
        return;
    }

    memcpy(combined_data, hash1, len1);
    memcpy(combined_data + len1, hash2, len2);
    
    unsigned char combined_hash[SHA256_DIGEST_LENGTH];
    unsigned int combined_len = SHA256_DIGEST_LENGTH;

    // Convert binary hash to hex string
    if(compute_sha256_hash(combined_data, total_length, combined_hash, &combined_len)){
        for (int i = 0; i < combined_len; i++) {
        /* final_hash + (i * 2) is address for hex string, since each byte is represented with two hexadecimal chars, offset is increased by 2*/
        /*3 for no of max chars to be written including null terminator*/
        /*%02x : %x converts unsigned integer to hexadecimal, 02 to padd with zeros if less than 2*/
        /*combined_hash for values to be formatted*/
        snprintf(final_hash + (i * 2), 3, "%02x", combined_hash[i]);
    }
    }
    free(combined_data);
}

// Utility function to check if name is valid
bool isValidName(const char *name){
    const char invalid_chars_name[] = "/:;<>,[]\t\n\r@.";
    if(name==NULL){
        printf("Need name input.\n");
        return false;
    }

    if(contains_invalid_chars(name, invalid_chars_name)){
        printf("Contains invalid characters.\n");
        return false;
    }

    if(!contains_alpha(name)){
        printf("Must contain at least one alphabetic character.\n");
        return false;
    }
    return true;
}

// Utility function to check if email is valid
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

// Utility function to convert password's entropy to crack time
double entropy_to_crack_time(double entropy) {
    return (pow(2, entropy - 1)) * SECONDS_PER_GUESS;
}

// Utility function to display password crack time
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
         (buffer, sizeof(buffer), "centuries");
    }
    return buffer;
}

// Utility function to check password's strength
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

// Generate fingerprint from image for cryptographic keys (Call at beginning of creating account)
void generate_fingerprint_from_image(const char *input_image, const char *user_id, const char *user_email, char *image_fingerprint) {
    char converted_image_path[256]; // buffer to store coverted path
    const char *image_path_to_use = input_image; // image to use for generating fingerprint
    FILE *fp = NULL;
    png_structp png_ptr = NULL;
    png_infop info_ptr = NULL;

    // Check if the input image is a JPEG or TIFF and convert it to PNG
    if (needsConversionToPNG(input_image)) {
        snprintf(converted_image_path, sizeof(converted_image_path), "%s.png", input_image);
        if (!convertImagetoPNG(input_image, converted_image_path)) {
            fprintf(stderr, "Failed to convert image to PNG.\n");
            return;
        }
        image_path_to_use = converted_image_path;
    }

    SDL_Surface *image = load_PNG_image(image_path_to_use, &fp, &png_ptr, &info_ptr);
    if(!image){
        fprintf(stderr, "Image loading failed.\n");
        return;
    }

    // Extract image specific metadata and combine with user data
    char metadata_string[2048] = {0}; // String to hash
    png_timep mod_time; // Last modification time of image
    png_textp text_ptr; // Textual data of image
    int num_text;

    // Metadata from PNG
    if (png_get_tIME(png_ptr, info_ptr, &mod_time)) {
        snprintf(metadata_string, sizeof(metadata_string), "%4d-%02d-%02d %02d:%02d:%02d ", mod_time->year, mod_time->month, mod_time->day, mod_time->hour, mod_time->minute, mod_time->second);
    }
    if (png_get_text(png_ptr, info_ptr, &text_ptr, &num_text)) {
        for (int i = 0; i < num_text; i++) {
            strncat(metadata_string, text_ptr[i].key, sizeof(metadata_string) - strlen(metadata_string) - 1);
            strncat(metadata_string, "=", sizeof(metadata_string) - strlen(metadata_string) - 1);
            strncat(metadata_string, text_ptr[i].text, sizeof(metadata_string) - strlen(metadata_string) - 1);
            strncat(metadata_string, "; ", sizeof(metadata_string) - strlen(metadata_string) - 1);
        }
    }

    // Include user-specific data
    /*metadata_string + strlen(metadata_string) calculates address in metadata_string array where it ends for appending user data, 
    sizeof(metadata_string) - strlen(metadata_string) calculates how much space left in buffer*/
    snprintf(metadata_string + strlen(metadata_string), sizeof(metadata_string) - strlen(metadata_string), " UserID: %s; Email: %s;", user_id, user_email);

    // Hashing both metadata and pixel data
    unsigned char metadata_hash[SHA256_DIGEST_LENGTH], pixel_hash[SHA256_DIGEST_LENGTH];
    unsigned int md_len = SHA256_DIGEST_LENGTH, px_len = SHA256_DIGEST_LENGTH;
    compute_sha256_hash((unsigned char*)metadata_string, strlen(metadata_string), metadata_hash, &md_len);
    compute_sha256_hash((unsigned char*)image->pixels, image->w * image->h * image->format->BytesPerPixel, pixel_hash, &px_len);

    // Combine hashes
    hash_and_combine(metadata_hash, md_len, pixel_hash, px_len, image_fingerprint);
    
    cleanup_SDL2_libpng(image, fp, png_ptr, info_ptr);
}

// Derive cryptographic keys from image fingerprint (Call at beginning of creating account)
void generate_key_from_image_fingerprint(const char *image_fingerprint, char *key, size_t key_len){
    // Check key length requirement
    if (key_len < crypto_kdf_BYTES_MIN || key_len > crypto_kdf_BYTES_MAX) {
        fprintf(stderr, "Requested key length %zu is out of acceptable range.\n", key_len);
        return;
    }

    unsigned char master_image_key[crypto_kdf_KEYBYTES];
    unsigned char binary_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // Convert SHA256 hexadecimal string to binary
    if (sodium_hex2bin(binary_fingerprint, sizeof(binary_fingerprint), image_fingerprint, strlen(image_fingerprint), NULL, NULL, NULL) != 0) {
        fprintf(stderr, "Failed to convert image fingerprint to binary.\n");
        return;
    }

    // Generate a random salt
    randombytes_buf(salt, sizeof(salt));

    // Generate a master key using Argon2
    if (crypto_pwhash(master_image_key, sizeof(master_image_key), (const char *)binary_fingerprint, sizeof(binary_fingerprint), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        fprintf(stderr, "Failed to generate master key from image fingerprint.\n");
        return;
    }

    // Derive a subkey from the image master key
    if (crypto_kdf_derive_from_key(key, key_len, 1, "082301\x00\x00", master_image_key) != 0) {
        fprintf(stderr, "Failed to derive key from master image key.\n");
        return;
    }
}

// Derive cryptographic keys from password
void generate_key_from_password(const char *password, char *key, size_t key_len){
    if(sodium_init() < 0){
        fprintf(stderr, "Failed to initialize libsodium.\n");
        return;
    }

    // Check key length requirement
    if(key_len < crypto_kdf_BYTES_MIN || key_len > crypto_kdf_BYTES_MAX){
        fprintf(stderr, "Requested key length %zu is out of acceptable range.\n", key_len);
        return;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char master_password_key[crypto_kdf_KEYBYTES];

    // Generate a random salt (nonce)
    randombytes_buf(salt, sizeof salt);

    // Derive a master key from the password with Argon2(since sensitive and non-interactive, use highest sensitive settings)
    if(crypto_pwhash(master_password_key, sizeof master_password_key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_ARGON2ID13) != 0){
        fprintf(stderr, "Failed to derive master key from password.\n");
        return;
    }

    // Derive a subkey from the master key
    if(crypto_kdf_derive_from_key(key, key_len, 1, "MMSKYI\x00\x00", master_password_key) != 0){
        fprintf(stderr, "Failed to derive cryptographic key from master password key.\n");
        return;
    }
}

// Utility function to encrypt data
bool encrypt_data(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext, size_t *ciphertext_len){
    // Generate nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Allocate memory for ciphertext
    size_t total_len = crypto_secretbox_MACBYTES + plaintext_len + crypto_secretbox_NONCEBYTES;
    *ciphertext = (unsigned char *)malloc(total_len);
    if(*ciphertext == NULL){
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        return false;
    }

    // Encrypt data
    crypto_secretbox_easy(*ciphertext, plaintext, plaintext_len, nonce, key);

    // Append nonce to the encrypted data
    memcpy(*ciphertext + crypto_secretbox_MACBYTES + plaintext_len, nonce, crypto_secretbox_NONCEBYTES);
    *ciphertext_len = total_len;
    return true;

    // For debugging 
    // printf("!-------------Encrypt Data Function-------------!\n");
    // printf("Ciphertext before appending nonce: ");
    // for (size_t i = 0; i < crypto_secretbox_MACBYTES + plaintext_len; i++) {
    //     printf("%02x", (*ciphertext)[i]);
    // }
    // printf("\n");

    // printf("Ciphertext: ");
    // for (size_t i = 0; i < *ciphertext_len; i++) {
    //     printf("%02x", (*ciphertext)[i]);
    // }
    // printf("\n");
    // printf("Ciphertext_len: %zu\n", *ciphertext_len);
    // printf("Nonce: ");
    // for(int i=0; i < sizeof nonce; i++){
    //     printf("%02x", nonce[i]);
    // }
    // printf("\n");
    // printf("!----------------------------------------------!\n");
    // printf("\n");
}

// Utility function to embed data into image using LSB steganography
bool embed_data_into_image(const char *input_image_path, const char *output_image_path, 
                           const unsigned char *ciphertext, size_t ciphertext_len) {
    if (!input_image_path || !output_image_path || !ciphertext || ciphertext_len == 0) {
        fprintf(stderr, "Invalid input parameters\n");
        return false;
    }

    SDL_Surface *image = IMG_Load(input_image_path);
    if (!image) {
        fprintf(stderr, "Unable to load image: %s\n", IMG_GetError());
        return false;
    }

    int width = image->w;
    int height = image->h;
    size_t pixel_count = (size_t)width * height;

    size_t total_bits_needed = (ciphertext_len + sizeof(size_t)) * 8; // bytes of cipher and its length * 8 = required bits
    if (total_bits_needed > pixel_count * 3) {  // Using 3 bits per pixel for increased capacity
        fprintf(stderr, "Data is too large to fit in the image.\n");
        SDL_FreeSurface(image);
        return false;
    }

    // Converting surface into RGBA
    SDL_Surface *workingSurface = SDL_ConvertSurfaceFormat(image, SDL_PIXELFORMAT_RGBA32, 0);
    SDL_FreeSurface(image);
    if (!workingSurface) {
        fprintf(stderr, "Unable to convert surface: %s\n", SDL_GetError());
        return false;
    }

    Uint32 *pixels = (Uint32 *)workingSurface->pixels;
    size_t pixel_index = 0;

    // Embed the length of data first (in little-endian format)
    for (size_t i = 0; i < sizeof(size_t); i++) {
        unsigned char byte_to_embed = (ciphertext_len >> (i * 8)) & 0xFF; // right-shift each byte of ciphertext_len by i * 8 bits, & 0xFF to mask the result with 0xFF to extract LSB
        // printf("Embedding length byte %zu: 0x%02x\n", i, byte_to_embed);
        for (int bit = 0; bit < 8; bit += 3, pixel_index++) { // 3 bits at a time in each pixel
            Uint32 pixel = pixels[pixel_index];
            Uint32 bits_to_embed = (byte_to_embed >> bit) & 0x07;
            pixel = (pixel & 0xFFFFFFF8) | bits_to_embed; // masks 3 ls bits with 0x07 , 0xFF for full byte and mask it with 0xFFFFFFF8 to clear last 3 bits of  pixel, the extracted 3 bits are then ORed with masked values, essentially embedding the bits into 3 ls bits of pixel
            pixels[pixel_index] = pixel;
            // printf("Pixel %zu: 0x%08x, Embedded bits: %d\n", pixel_index, pixel, bits_to_embed);
        }
    }

    // Embed the ciphertext
    for (size_t i = 0; i < ciphertext_len; i++) {
        for (int bit = 0; bit < 8; bit += 3, pixel_index++) {
            Uint32 pixel = pixels[pixel_index];
            Uint32 bits_to_embed = (ciphertext[i] >> bit) & 0x07;
            pixel = (pixel & 0xFFFFFFF8) | bits_to_embed;  
            pixels[pixel_index] = pixel;
        }
    }

    // Save the modified image
    if (IMG_SavePNG(workingSurface, output_image_path) != 0) {
        fprintf(stderr, "Unable to save image: %s\n", IMG_GetError());
        SDL_FreeSurface(workingSurface);
        return false;
    }

    SDL_FreeSurface(workingSurface);
    return true;
}

// Function to extract encrypted data from an image
bool extract_data_from_image(const char *encrypted_image_path, unsigned char **ciphertext, size_t *ciphertext_len) {
    if (!encrypted_image_path || !ciphertext || !ciphertext_len) {
        fprintf(stderr, "Invalid input parameters\n");
        return false;
    }

    *ciphertext = NULL;
    *ciphertext_len = 0;

    SDL_Surface *image = IMG_Load(encrypted_image_path);
    if (!image) {
        fprintf(stderr, "Failed to load image: %s\n", IMG_GetError());
        return false;
    }

    SDL_Surface *workingSurface = SDL_ConvertSurfaceFormat(image, SDL_PIXELFORMAT_RGBA32, 0);
    SDL_FreeSurface(image);
    if (!workingSurface) {
        fprintf(stderr, "Unable to convert surface: %s\n", SDL_GetError());
        return false;
    }

    int width = workingSurface->w;
    int height = workingSurface->h;
    size_t pixel_count = (size_t)width * height;
    Uint32 *pixels = (Uint32 *)workingSurface->pixels;

    // Extract the length of the data first
    size_t extracted_len = 0;
    size_t pixel_index = 0;
    for (size_t i = 0; i < sizeof(size_t); i++) {
        unsigned char current_byte = 0;
        for (int bit = 0; bit < 8; bit += 3, pixel_index++) {
            Uint32 pixel = pixels[pixel_index];
            unsigned char extracted_bits = pixel & 0x07;
            current_byte |= extracted_bits << bit;
            // printf("Pixel %zu: 0x%08x, Extracted bits: %d\n", pixel_index, pixel, extracted_bits);
        }
        extracted_len |= (size_t)current_byte << (i * 8);
        // printf("Byte %zu: 0x%02x, Current extracted_len: %zu\n", i, current_byte, extracted_len);
    }

    // printf("Final extracted length: %zu\n", extracted_len);

    size_t total_bits_needed = (extracted_len + sizeof(size_t)) * 8;
    if (extracted_len == 0 || total_bits_needed > pixel_count * 3) {
        fprintf(stderr, "Extracted length %zu is implausible or too large for image.\n", extracted_len);
        SDL_FreeSurface(workingSurface);
        return false;
    }

    // Allocate memory for the extracted data
    *ciphertext_len = extracted_len;
    *ciphertext = (unsigned char *)malloc(*ciphertext_len);
    if (*ciphertext == NULL) {
        fprintf(stderr, "Memory allocation failed for ciphertext.\n");
        SDL_FreeSurface(workingSurface);
        return false;
    }

    // Extract the actual data
    for (size_t i = 0; i < *ciphertext_len; i++) {
        (*ciphertext)[i] = 0;
        for (int bit = 0; bit < 8; bit += 3, pixel_index++) {
            Uint32 pixel = pixels[pixel_index];
            (*ciphertext)[i] |= (pixel & 0x07) << bit;
        }
    }

    SDL_FreeSurface(workingSurface);
    return true;
}

// Utility function to decrypt data
bool decrypt_data(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len){
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    // Extract the nonce from the end of the ciphertext
    memcpy(nonce, ciphertext + ciphertext_len - crypto_secretbox_NONCEBYTES, crypto_secretbox_NONCEBYTES);

    // Decrypt the data
    if(crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len - crypto_secretbox_NONCEBYTES, nonce, key) != 0){
        fprintf(stderr, "Decrypton failed. Unable to open secretbox.\n");
        *plaintext_len = 0;
        return false;
    }

    *plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES;

    // Print the decrypted data
    // printf("Decrypted data length: %zu\n", *plaintext_len);
    // printf("Decrypted data: ");
    // for(size_t i=0; i < *plaintext_len; i++){
    //     printf("%02x", plaintext_len[i]);
    // }
    // printf("\n");
    return true;
}

bool encrypt_credentials_into_image(const char *master_password_key, const char *master_image_key,
                                    const char *account_username, const char *account_domain, const char *account_pwd,
                                    const char *input_image, char *output_image) {
    EncryptedPart parts[3] = {0};  // username, domain, password
    size_t total_length = 0;

    // Encrypt each part
    if (!encrypt_data((const unsigned char *)master_password_key, (const unsigned char *)account_username, strlen(account_username), &parts[0].data, &parts[0].length) ||
        !encrypt_data((const unsigned char *)master_password_key, (const unsigned char *)account_domain, strlen(account_domain), &parts[1].data, &parts[1].length) ||
        !encrypt_data((const unsigned char *)master_image_key, (const unsigned char *)account_pwd, strlen(account_pwd), &parts[2].data, &parts[2].length)) {
        goto cleanup;  // Error occurred during encryption
    }

    // Calculate total length
    for (int i = 0; i < 3; i++) {
        total_length += parts[i].length;
    }

    // Allocate buffer for combined data
    unsigned char *encrypted_data = malloc(total_length);
    if (!encrypted_data) {
        fprintf(stderr, "Failed to allocate memory for encrypted data.\n");
        goto cleanup;
    }

    // Combine encrypted parts
    size_t offset = 0;
    for (int i = 0; i < 3; i++) {
        memcpy(encrypted_data + offset, parts[i].data, parts[i].length);
        offset += parts[i].length;
    }

    // Embed data into image
    bool success = embed_data_into_image(input_image, output_image, encrypted_data, total_length);
    
    if (success) {
        printf("Successfully embedded %zu bytes of encrypted data into image.\n", total_length);
    } else {
        fprintf(stderr, "Failed to embed data into image.\n");
    }

    free(encrypted_data);

cleanup:
    for (int i = 0; i < 3; i++) {
        free(parts[i].data);
    }
    
    return success;
}

bool decrypt_credentials_from_image(const unsigned char *master_password_key, const unsigned char *master_image_key,
                                    const char *input_image, char *account_username, char *account_domain, char *account_pwd,
                                    size_t max_username_len, size_t max_domain_len, size_t max_password_len) {
    unsigned char *encrypted_data = NULL;
    size_t encrypted_data_len;
    bool success = false;

    // Extract encrypted data from the image
    if (!extract_data_from_image(input_image, &encrypted_data, &encrypted_data_len)) {
        fprintf(stderr, "Failed to extract data from image.\n");
        return false;
    }

    printf("Extracted data length: %zu\n", encrypted_data_len);

    // Define maximum encrypted lengths
    const size_t max_encrypted_len = crypto_secretbox_MACBYTES + 256 + crypto_secretbox_NONCEBYTES;

    // Determine lengths of each component
    size_t encrypted_lengths[3] = {0};
    size_t remaining_len = encrypted_data_len;
    for (int i = 0; i < 3 && remaining_len > 0; i++) { // Run for 3 iterations for each component
        encrypted_lengths[i] = (remaining_len > max_encrypted_len) ? max_encrypted_len : remaining_len; // ternary operator between remaining len and max_encrypted_len to assign encrypted_lengths for each component
        remaining_len -= encrypted_lengths[i]; 
    }

    // Print length of each component for debugging
    // printf("Encrypted username length: %zu\n", encrypted_lengths[0]);
    // printf("Encrypted domain length: %zu\n", encrypted_lengths[1]);
    // printf("Encrypted password length: %zu\n", encrypted_lengths[2]);

    // Decrypt each part
    unsigned char *decrypted_parts[3] = {NULL, NULL, NULL};
    size_t decrypted_lengths[3] = {0};
    const unsigned char *keys[3] = {master_password_key, master_password_key, master_image_key};
    size_t max_lengths[3] = {max_username_len, max_domain_len, max_password_len};

    for (int i = 0; i < 3; i++) {
        decrypted_parts[i] = malloc(max_lengths[i]);
        if (!decrypted_parts[i]) {
            fprintf(stderr, "Memory allocation failed for decrypted part %d.\n", i);
            goto cleanup;
        }

        if (!decrypt_data(keys[i], encrypted_data + (i > 0 ? encrypted_lengths[i-1] : 0), 
                          encrypted_lengths[i], decrypted_parts[i], &decrypted_lengths[i])) { // second argument calculates the starting address of ciphertext (i.e. for 0, beginning of cipher, for following, calculate next address by adding the lengths of previous parts)
            fprintf(stderr, "Decryption failed for part %d.\n", i);
            goto cleanup;
        }

        if (decrypted_lengths[i] >= max_lengths[i]) {
            fprintf(stderr, "Decrypted part %d is too long.\n", i);
            goto cleanup;
        }

        decrypted_parts[i][decrypted_lengths[i]] = '\0';
    }

    // Copy decrypted data to output buffers
    strncpy(account_username, (char *)decrypted_parts[0], max_username_len);
    strncpy(account_domain, (char *)decrypted_parts[1], max_domain_len);
    strncpy(account_pwd, (char *)decrypted_parts[2], max_password_len);

    success = true;

cleanup:
    // Free allocated memory
    free(encrypted_data);
    for (int i = 0; i < 3; i++) {
        if (decrypted_parts[i]) {
            sodium_memzero(decrypted_parts[i], max_lengths[i]);
            free(decrypted_parts[i]);
        }
    }

    return success;
}

void generate_random_password(const char *username, const char *domain, char *password) {
    const char *upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *lower = "abcdefghijklmnopqrstuvwxyz";
    const char *digits = "0123456789";
    const char *specials = "!@#$%%^&*()-_";
    int length = 15;  // minimum length of 15

    srand((unsigned int)time(NULL));

    while (1){
        int pos = 0;
        // Ensuring at least one character from each required set
        password[pos++] = upper[rand() % strlen(upper)];
        password[pos++] = lower[rand() % strlen(lower)];
        password[pos++] = digits[rand() % strlen(digits)];
        password[pos++] = specials[rand() % strlen(specials)];

        // Filling the rest of the password
        while (pos < length) {
            int r = rand() % 4;
            switch(r) {
                case 0:
                    password[pos++] = upper[rand() % strlen(upper)];
                    break;
                case 1:
                    password[pos++] = lower[rand() % strlen(lower)];
                    break;
                case 2:
                    password[pos++] = digits[rand() % strlen(digits)];
                    break;
                case 3:
                    password[pos++] = specials[rand() % strlen(specials)];
                    break;
            }
        }

        password[pos] = '\0'; // Null-terminating the string

        // Validate password strength
        if (isStrongPassword(password)) {
            break;
        }
    }
}

// Structure to hold email data
struct upload_status {
    const char *data;
    size_t bytes_read;
};

// Callback function for CURL to read the email body
static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct upload_status *upload_ctx = (struct upload_status *)userp;
    const char *data;
    size_t room = size * nmemb;

    if ((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
        return 0;
    }

    data = upload_ctx->data + upload_ctx->bytes_read;

    if (data) {
        size_t len = strlen(data);
        if (room < len)
            len = room;
        memcpy(ptr, data, len);
        upload_ctx->bytes_read += len;
        return len;
    }

    return 0;
}