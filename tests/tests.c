#include <stdio.h>
#include "test_libs.h"

int main() {
    const char *png_file_name = "test.png"; 
    const char *jpeg_file_name = "test.jfif"; 

    printf("Testing png image display function...\n");
    display_png_info(png_file_name);
    printf("Testing jpeg image display function...\n \n");
    display_jpeg_info(jpeg_file_name);

    return 0;
}