#define _GNU_SOURCE
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int
callback(struct dl_phdr_info* info, size_t size, void* data) {
    char* type;
    int p_type;

    printf("Name: \"%s\" (%d segments)\n", info->dlpi_name, info->dlpi_phnum);

    for (int j = 0; j < info->dlpi_phnum; j++) {
        p_type = info->dlpi_phdr[j].p_type;
        type = (p_type == PT_LOAD)           ? "PT_LOAD"
               : (p_type == PT_DYNAMIC)      ? "PT_DYNAMIC"
               : (p_type == PT_INTERP)       ? "PT_INTERP"
               : (p_type == PT_NOTE)         ? "PT_NOTE"
               : (p_type == PT_INTERP)       ? "PT_INTERP"
               : (p_type == PT_PHDR)         ? "PT_PHDR"
               : (p_type == PT_TLS)          ? "PT_TLS"
               : (p_type == PT_GNU_EH_FRAME) ? "PT_GNU_EH_FRAME"
               : (p_type == PT_GNU_STACK)    ? "PT_GNU_STACK"
               : (p_type == PT_GNU_RELRO)    ? "PT_GNU_RELRO"
                                             : NULL;

        /*
        printf("    %2d: [%14p; memsz:%7jx] flags: %#jx; ", j,
               (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
               (uintmax_t)info->dlpi_phdr[j].p_memsz, (uintmax_t)info->dlpi_phdr[j].p_flags);
          */
          puts(info->dlpi_name);     
        if (type != NULL)
            printf("%s\n", type);
        else
            printf("[other (%#x)]\n", p_type);

        pid_t pid = fork();
        if (pid == -1) {
            fprintf(stderr, "AAAAAA\n");
            exit(1);
        }        
        if (!pid) {
            // Child
            char* const args[] = {
                "/usr/bin/addr2line",
                "-e",
                "a.out",
                "0x1",NULL
            };
            if (execv(args[0], args)) {
                perror("Execv error");
            };
            return 0;
        } else {
            // Parent
            int status;
            waitpid(pid, &status, 0);
        }
    }

    return 0;
}

int
main(int argc, char* argv[]) {
    dl_iterate_phdr(callback, NULL);

    exit(EXIT_SUCCESS);
}
