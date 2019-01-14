#include <malloc.h>

#include "answer.h"

ElfData getELFData(const char* executable) {
    ElfData elfData;

    return elfData;
}

void destroyELFData(ElfData elfData) {
    // This demonstrates valgrind leak detection.
    char* leak = malloc(1);
}
