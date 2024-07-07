#include <stdio.h>
#include "test_libs.h"

int main() {
    const char *png_file_name = "test.png"; 
    const char *jpeg_file_name = "test.jpg"; 

    printf("Testing png image display function in CLI...\n");
    display_png_info_CLI(png_file_name);
    printf("Testing png image display function in GUI...\n");
    display_image_GUI(png_file_name);
    printf("\nTesting jpeg image display function in CLI...\n");
    display_jpeg_info(jpeg_file_name);
    printf("Testing jpeg image display function in GUI...\n");
    display_image_GUI(jpeg_file_name);

    return 0;
}