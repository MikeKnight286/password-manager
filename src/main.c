#include <png.h>
#include <jpeglib.h>
#include <stdio.h>
#include "utils.h"

int main() {
    printf("Starting program...\n");
    fflush(stdout);

    printf("libpng version: %s\n", png_get_libpng_ver(NULL));
    fflush(stdout);

    printf("libjpeg version: %d\n", JPEG_LIB_VERSION);
    fflush(stdout);

    printf("Ending program...\n");
    fflush(stdout);

    utils();

    return 0;
}
