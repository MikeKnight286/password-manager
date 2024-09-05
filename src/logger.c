#include "logger.h"
#include <stdarg.h>

static const char* level_strings[] = {
    "DEBUG", "INFO", "WARNING", "ERROR"
};

void log_message(LogLevel level, const char* file, int line, const char* message, ...) {
    va_list args;
    char timestamp[20];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(stderr, "[%s] %s:%d [%s] ", timestamp, file, line, level_strings[level]);
    
    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
    
    fprintf(stderr, "\n");
}