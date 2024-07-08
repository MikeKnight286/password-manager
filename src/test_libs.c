#include <stdio.h>
#include <png.h>
#include <jpeglib.h>
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <sodium.h>
#include <string.h>
#include "test_libs.h"

// PNG IMAGE DISPLAY TEST
void display_png_info_CLI(const char *file_name) {
    printf("libpng version: %s\n", png_get_libpng_ver(NULL));
    fflush(stdout);

    FILE *fp = fopen(file_name, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Unable to open file %s\n", file_name);
        return;
    }

    // Struct to store info and state of PNG file
    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        fprintf(stderr, "Error: Unable to create PNG read struct\n");
        fclose(fp);
        return;
    }

    // Struct to store metadata of PNG file
    png_infop info = png_create_info_struct(png);
    if (!info) {
        fprintf(stderr, "Error: Unable to create PNG info struct\n");
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return;
    }

    // Error handler struct with pointer for longjmp to jump back to (save this env)
    if (setjmp(png_jmpbuf(png))) {
        fprintf(stderr, "Error: An error occurred during PNG read\n");
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return;
    }

    // Initiate input/output for PNG file to a file ptr and r/w it
    png_init_io(png, fp);
    png_read_info(png, info);

    int width = png_get_image_width(png, info);
    int height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth = png_get_bit_depth(png, info);

    printf("Width: %d\n", width);
    printf("Height: %d\n", height);
    printf("Color Type: %d\n", color_type);
    printf("Bit Depth: %d\n", bit_depth);

    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
}

// JPEG IMAGE DISPLAY TEST
void display_jpeg_info(const char *file_name){

    printf("libjpeg version: %d\n", JPEG_LIB_VERSION);
    fflush(stdout);

    FILE *fp = fopen(file_name, "rb"); 
    if (!fp) {
        fprintf(stderr, "Error: Unable to open file %s\n", file_name);
        return;
    }

    struct jpeg_decompress_struct cinfo; // Struct for JPG/JPEG file for storing info
    struct jpeg_error_mgr jerr; // Error handler 
    
    cinfo.err = jpeg_std_error(&jerr); // Assign error field to address of handler
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, fp);
    jpeg_read_header(&cinfo, TRUE);
    jpeg_start_decompress(&cinfo);

    printf("Width: %d\n", cinfo.output_width);
    printf("Height: %d\n", cinfo.output_height);
    printf("Color Components: %d\n", cinfo.output_components);

    // Allocating scanline buffer
    JSAMPARRAY buffer = (*cinfo.mem->alloc_sarray)((j_common_ptr) &cinfo, JPOOL_IMAGE, cinfo.output_width * cinfo.output_components, 1); // allocate 2D array to memory, w x h for no of samples and 1 for 1 row
    while (cinfo.output_scanline < cinfo.output_height) {
        jpeg_read_scanlines(&cinfo, buffer, 1);
    } // read each scanline in a loop until image is fully read into buffer

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    fclose(fp);
}

// IMAGE RENDER TEST WITH SDL LIB
void display_image_GUI(const char *file_name){
    // Initializes video
    if (SDL_Init(SDL_INIT_VIDEO) < 0){
        fprintf(stderr, "Could not initialize SDL: %s\n", SDL_GetError());
        return;
    }

    // Create window ptr 
    SDL_Window *window = SDL_CreateWindow("Image Display",
                                            SDL_WINDOWPOS_UNDEFINED,
                                            SDL_WINDOWPOS_UNDEFINED,
                                            800, 600,
                                            SDL_WINDOW_SHOWN);

    if (!window){
        fprintf(stderr, "Could not create window: %s\n", SDL_GetError());
        SDL_Quit();
        return;
    }

    // Render image from window ptr, uses hardware acceleration
    SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    if (!renderer){
        fprintf(stderr, "Could not create renderer: %s\n", SDL_GetError());
        SDL_DestroyWindow(window);
        SDL_Quit();
        return;
    }

    // Store raw pixel data and bimap of image in surface
    SDL_Surface *image_surface = IMG_Load(file_name);
    if (!image_surface) {
        fprintf(stderr, "Could not load image: %s\n", IMG_GetError());
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return;
    }

    // Create texture from bitmap stored in surface
    SDL_Texture *image_texture = SDL_CreateTextureFromSurface(renderer, image_surface);
    SDL_FreeSurface(image_surface);
    if (!image_texture) {
        fprintf(stderr, "Could not create texture: %s\n", SDL_GetError());
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return;
    }

    SDL_RenderClear(renderer);
    SDL_RenderCopy(renderer, image_texture, NULL, NULL);
    SDL_RenderPresent(renderer);

    SDL_Event e; // instance to hold events
    int quit = 0; 
    while(!quit) {
        // if there are any event at address of instance e, change the flag to 1
        while(SDL_PollEvent(&e)){ 
            if(e.type == SDL_QUIT) {
                quit = 1;
            }
        }
    }

    SDL_DestroyTexture(image_texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
}

void argon2_hash_string(const char *input_string){
    if (sodium_init() < 0){
        fprintf(stderr, "Failed to initialize libsodium\n");
        return;
    }

    char hashed_string[crypto_pwhash_STRBYTES]; //buffer to hold hashed string

    if (crypto_pwhash_str(
            hashed_string,
            input_string,
            strlen(input_string),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, //typically 4 s
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0){ //typically 32 MB
        fprintf(stderr, "Failed to hash input string\n");
        return;
    }
    
    printf("Argon2 hash of \"%s\" : %s\n", input_string, hashed_string);
}
