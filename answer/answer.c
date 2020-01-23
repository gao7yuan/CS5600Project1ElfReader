#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "answer.h"

ElfData getELFData(const char *executable) {
    ElfData elfData;

    /*
     * Map executable file onto memory.
     */

    char *map_start; // starting address in memory for mapping
    int fd; // file descriptor
    struct stat file_stat; // file stat

    fd = open(executable, O_RDONLY);

    // handle error if cannot open file
    if (fd == -1) {
        perror("ERROR: open (file does not exist)\n");
        bzero(&elfData, sizeof(elfData)); // pack zeroes to the space for elfData
        return elfData;
    }
    // obtain file size
    if (fstat(fd, &file_stat) == -1) {
        perror("ERROR: fstat\n");
        bzero(&elfData, sizeof(elfData));
        return elfData;
    }

    // map file to memory
    map_start = mmap((void *) 0, (size_t) file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    // handle error for failed mapping
    if (map_start == MAP_FAILED) {
        perror("ERROR: mmap\n");
        bzero(&elfData, sizeof(elfData));
        return elfData;
    }

    /*
     * Extract ELF file info from memory.
     */

    /* read elf header */

    // copy elf header data from memory to elfData
    memcpy(&elfData.elfHeader, map_start, sizeof(Elf64_Ehdr));
    // handle error if not elf file
    if (memcmp(elfData.elfHeader.e_ident, ELFMAG, 4) != 0) {
        perror("ERROR: not an elf file\n");
        bzero(&elfData, sizeof(elfData));
        return elfData;
    }

    /* program header */

    Elf64_Phdr *programHeader = NULL; // default for program header is NULL
    // if program header offset is 0, or number of program headers in elf file is 0,
    // then program header is NULL; otherwise read and copy from memory
    if (elfData.elfHeader.e_phoff != 0 && elfData.elfHeader.e_phnum != 0) {
        Elf64_Phdr *phdr_ptr = (Elf64_Phdr * )(
                map_start + elfData.elfHeader.e_phoff); // program header pointer in memory
        programHeader = (Elf64_Phdr *) malloc(
                elfData.elfHeader.e_phnum * sizeof(Elf64_Phdr)); // malloc array for copying program headers
        // copy program headers
        memcpy(programHeader, phdr_ptr, elfData.elfHeader.e_phnum * sizeof(Elf64_Phdr));
    }

    // assign value to related field
    elfData.programHeader = programHeader;

    /* sections */

    ElfSection *sections = NULL; // default sections is NULL if section header in elf file is empty
    // if section header offset is 0 and number of section headers in elf file is 0,
    // then sections is NULL; otherwise read from memory and copy
    if (elfData.elfHeader.e_shoff != 0 && elfData.elfHeader.e_shnum != 0) {
        Elf64_Shdr *shdr_ptr = (Elf64_Shdr * )(map_start + elfData.elfHeader.e_shoff); // pointer to section header
        sections = (ElfSection *) malloc(elfData.elfHeader.e_shnum * sizeof(ElfSection)); // malloc array for sections
        // copy section headers one by one
        for (int i = 0; i < elfData.elfHeader.e_shnum; i++) {
            memcpy(&(sections[i].sectionHeader), &shdr_ptr[i], sizeof(Elf64_Shdr));
            sections[i].sectionName = NULL; // initialize sectionName, which will be assigned other values later
        }
    }

    // add sections names by obtaining the names from section name string table
    if (sections != NULL) {
        for (int i = 0; i < elfData.elfHeader.e_shnum; i++) {
            // find the section name in memory by finding the offset of it
            // starting address + offset of section name string table + index (offset) of section name
            char *sh_name_ptr = map_start + sections[elfData.elfHeader.e_shstrndx].sectionHeader.sh_offset +
                                sections[i].sectionHeader.sh_name;
            // copy section name string to sectionName field
            sections[i].sectionName = strdup(sh_name_ptr);
        }
    }

    // assign value to related field
    elfData.sections = sections;

    /* symbols */

    // default values for dynamic symbols and other symbols pointers in memory: NULL
    Elf64_Sym *dynsym_ptr = NULL;
    Elf64_Sym *othersym_ptr = NULL;
    // default values for string table pointer for related symbol tables in memory: NULL
    char *dynsym_str_ptr = NULL;
    char *othersym_str_ptr = NULL;
    // default number of dynamic symbols and other symbols: 0
    int num_dynsym = 0;
    int num_othersym = 0;

    // default values for symbol lists
    elfData.dynSymbols.list = NULL;
    elfData.otherSymbols.list = NULL;
    elfData.dynSymbols.size = 0;
    elfData.otherSymbols.size = 0;

    if (sections != NULL) {
        // go through all the sections and find dynamic symbols, string table for dynamic symbols,
        // other symbols, and string table for other symbols
        for (int i = 0; i < elfData.elfHeader.e_shnum; i++) {
            // catch symbol pointers and symbol sizes
            if (strcmp(sections[i].sectionName, ".dynsym") == 0) {
                dynsym_ptr = (Elf64_Sym * )(map_start + sections[i].sectionHeader.sh_offset);
                // number of dynamic symbols = section size / size of one entry
                num_dynsym = sections[i].sectionHeader.sh_size / sections[i].sectionHeader.sh_entsize;
            }
            if (strcmp(sections[i].sectionName, ".symtab") == 0) {
                othersym_ptr = (Elf64_Sym * )(map_start + sections[i].sectionHeader.sh_offset);
                // number of other symbols = section size / size of one entry
                num_othersym = sections[i].sectionHeader.sh_size / sections[i].sectionHeader.sh_entsize;
            }
            // catch pointers to symbol string names
            if (strcmp(sections[i].sectionName, ".dynstr") == 0) {
                dynsym_str_ptr = map_start + sections[i].sectionHeader.sh_offset;
            }
            if (strcmp(sections[i].sectionName, ".strtab") == 0) {
                othersym_str_ptr = map_start + sections[i].sectionHeader.sh_offset;
            }
        }
    }

    if (dynsym_ptr != NULL && num_dynsym != 0) {
        elfData.dynSymbols.list = (ElfSymbol *) malloc(num_dynsym * sizeof(ElfSymbol));
        for (int i = 0; i < num_dynsym; i++) {
            // copy symbol
            memcpy(&elfData.dynSymbols.list[i].symbol, &dynsym_ptr[i], sizeof(Elf64_Sym));
            elfData.dynSymbols.list[i].name = NULL; // default name is NULL unless st_name is nonzero
            if (elfData.dynSymbols.list[i].symbol.st_name != 0) {
                char *name = (char *) (dynsym_str_ptr + elfData.dynSymbols.list[i].symbol.st_name);
//                elfData.dynSymbols.list[i].name = (char *) malloc(strlen(name) + 1);
//                memcpy(elfData.dynSymbols.list[i].name, name, strlen(name));
                elfData.dynSymbols.list[i].name = strdup(name);
            }
        }
        elfData.dynSymbols.size = num_dynsym;
    }

    if (othersym_ptr != NULL && num_othersym != 0) {
        elfData.otherSymbols.list = (ElfSymbol *) malloc(num_othersym * sizeof(ElfSymbol));
        for (int i = 0; i < num_othersym; i++) {
            // copy symbol
            memcpy(&elfData.otherSymbols.list[i].symbol, &othersym_ptr[i], sizeof(Elf64_Sym));
            elfData.otherSymbols.list[i].name = NULL; // default name is NULL unless st_name is nonzero
            if (elfData.otherSymbols.list[i].symbol.st_name != 0) {
                char *name = (char *) (othersym_str_ptr + elfData.otherSymbols.list[i].symbol.st_name);
//                size_t len = strlen(name) + 1;
//                elfData.otherSymbols.list[i].name = (char *) malloc(len);
//                memcpy(elfData.otherSymbols.list[i].name, name, strlen(name));
                elfData.otherSymbols.list[i].name = strdup(name);
            }
        }
        elfData.otherSymbols.size = num_othersym;
    }

    // finished mapping
    munmap(map_start, (size_t) file_stat.st_size);


    return elfData;
}

void destroyELFData(ElfData elfData) {
    // This demonstrates valgrind leak detection.
//    char *leak = malloc(1);

    // programHeader
    if (elfData.programHeader != NULL) {
        free(elfData.programHeader);
        elfData.programHeader = NULL;
    }

    // sections
    if (elfData.sections != NULL) {
        for (int i = 0; i < elfData.elfHeader.e_shnum; i++) {
            free(elfData.sections[i].sectionName);
            elfData.sections[i].sectionName = NULL;
        }
        free(elfData.sections);
        elfData.sections = NULL;
    }

    // symbols
    if (elfData.dynSymbols.list != NULL) {
        for (int i = 0; i < elfData.dynSymbols.size; i++) {
            if (elfData.dynSymbols.list[i].name != NULL) {
                free(elfData.dynSymbols.list[i].name);
                elfData.dynSymbols.list[i].name = NULL;
            }
        }
        free(elfData.dynSymbols.list);
        elfData.dynSymbols.list = NULL;
    }

    if (elfData.otherSymbols.list != NULL) {
        for (int i = 0; i < elfData.otherSymbols.size; i++) {
            if (elfData.otherSymbols.list[i].name != NULL) {
                free(elfData.otherSymbols.list[i].name);
                elfData.otherSymbols.list[i].name = NULL;
            }
        }
        free(elfData.otherSymbols.list);
        elfData.otherSymbols.list = NULL;
    }

}