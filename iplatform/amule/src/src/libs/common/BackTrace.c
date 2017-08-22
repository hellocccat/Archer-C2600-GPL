/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Porting from android code: https://github.com/GeekRom/android_system_core/blob/master/libcorkscrew
 * Merged all codes we need into this file, 
 * Fix some problem to make it can work on mips,
 * Add some code for own use.
 *
 * Done By Chenjinfu.
 */
#ifdef HAVE_INNER_BACKTRACE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <elf.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <unwind.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#if defined(HAVE_BFD)
	#include <ansidecl.h>
	#include <bfd.h>
#endif

#define ALOGV(f, a...) //printf(f "\r\n",##a)

#define CORKSCREW_HAVE_ARCH 1

static void dump_hex(void*p,int len);

typedef struct {
    const char *dli_fname;/* Filename of defining object */
    void *dli_fbase;      /* Load address of that object */
    const char *dli_sname;/* Name of nearest lower symbol */
    void *dli_saddr;      /* Exact value of nearest symbol */
} Dl_info;

int *dladdr(const void *addr, Dl_info *info);

typedef struct {
    uintptr_t start;
    uintptr_t end;
    char* name;
} symbol_t;

typedef struct {
    symbol_t* symbols;
    size_t num_symbols;
} symbol_table_t;

 /* Custom extra data we stuff into map_info_t structures as part
 * of our ptrace_context_t. */
typedef struct {
    symbol_table_t* symbol_table;
} map_info_data_t;

/*
 * Loads a symbol table from a given file.
 * Returns NULL on error.
 */
symbol_table_t* load_symbol_table(const char* filename);

/*
 * Frees a symbol table.
 */
void free_symbol_table(symbol_table_t* table);

/*
 * Finds a symbol associated with an address in the symbol table.
 * Returns NULL if not found.
 */
const symbol_t* find_symbol(const symbol_table_t* table, uintptr_t addr);

typedef struct map_info {
    struct map_info* next;
    uintptr_t start;
    uintptr_t end;
    bool is_readable;
    bool is_writable;
    bool is_executable;
    void* data; // arbitrary data associated with the map by the user, initially NULL
    char name[];
} map_info_t;

void load_ptrace_map_info_data_arch(pid_t pid, map_info_t* mi, map_info_data_t* data);
void free_ptrace_map_info_data_arch(map_info_t* mi, map_info_data_t* data);
void load_ptrace_map_info_data_arch(pid_t pid, map_info_t* mi, map_info_data_t* data) {
}
void free_ptrace_map_info_data_arch(map_info_t* mi, map_info_data_t* data) {
}

static pid_t gettid() {
  return syscall(__NR_gettid);
}

static int tgkill(int tgid, int tid, int sig) {
  return syscall(__NR_tgkill, tgid, tid, sig);
}

/* Stores information about a process that is used for several different
 * ptrace() based operations. */
typedef struct {
    map_info_t* map_info_list;
} ptrace_context_t;

/* Describes how to access memory from a process. */
typedef struct {
    pid_t tid;
    const map_info_t* map_info_list;
} memory_t;

typedef struct pt_regs_mips {
    uint64_t regs[32];
    uint64_t lo;
    uint64_t hi;
    uint64_t cp0_epc;
    uint64_t cp0_badvaddr;
    uint64_t cp0_status;
    uint64_t cp0_cause;
} pt_regs_mips_t;

/*
 * Initializes a memory structure for accessing memory from this process.
 */
void init_memory(memory_t* memory, const map_info_t* map_info_list);

/*
 * Initializes a memory structure for accessing memory from another process
 * using ptrace().
 */
void init_memory_ptrace(memory_t* memory, pid_t tid);

/*
 * Reads a word of memory safely.
 * If the memory is local, ensures that the address is readable before dereferencing it.
 * Returns false and a value of 0xffffffff if the word could not be read.
 */
bool try_get_word(const memory_t* memory, uintptr_t ptr, uint32_t* out_value);

/*
 * Reads a word of memory safely using ptrace().
 * Returns false and a value of 0xffffffff if the word could not be read.
 */
bool try_get_word_ptrace(pid_t tid, uintptr_t ptr, uint32_t* out_value);

/*
 * Loads information needed for examining a remote process using ptrace().
 * The caller must already have successfully attached to the process
 * using ptrace().
 *
 * The context can be used for any threads belonging to that process
 * assuming ptrace() is attached to them before performing the actual
 * unwinding.  The context can continue to be used to decode backtraces
 * even after ptrace() has been detached from the process.
 */
ptrace_context_t* load_ptrace_context(pid_t pid);

/*
 * Frees a ptrace context.
 */
void free_ptrace_context(int pid, ptrace_context_t* context);

/*
 * Finds a symbol using ptrace.
 * Returns the containing map and information about the symbol, or
 * NULL if one or the other is not available.
 */
void find_symbol_ptrace(const ptrace_context_t* context,
        uintptr_t addr, const map_info_t** out_map_info, const symbol_t** out_symbol);


/* Loads memory map from /proc/<tid>/maps. */
map_info_t* load_map_info_list(pid_t tid);

/* Frees memory map. */
void free_map_info_list(map_info_t* milist);

/* Finds the memory map that contains the specified address. */
const map_info_t* find_map_info(const map_info_t* milist, uintptr_t addr);

/* Returns true if the addr is in a readable map. */
bool is_readable_map(const map_info_t* milist, uintptr_t addr);
/* Returns true if the addr is in a writable map. */
bool is_writable_map(const map_info_t* milist, uintptr_t addr);
/* Returns true if the addr is in an executable map. */
bool is_executable_map(const map_info_t* milist, uintptr_t addr);

/* Acquires a reference to the memory map for this process.
 * The result is cached and refreshed automatically.
 * Make sure to release the map info when done. */
map_info_t* acquire_my_map_info_list();

/* Releases a reference to the map info for this process that was
 * previous acquired using acquire_my_map_info_list(). */
void release_my_map_info_list(map_info_t* milist);

/*
 * Describes a single frame of a backtrace.
 */
typedef struct {
    uintptr_t absolute_pc;     /* absolute PC offset */
    uintptr_t stack_top;       /* top of stack for this frame */
    size_t stack_size;         /* size of this stack frame */
} backtrace_frame_t;

/*
 * Describes the symbols associated with a backtrace frame.
 */
typedef struct {
    uintptr_t relative_pc;       /* relative frame PC offset from the start of the library,
                                    or the absolute PC if the library is unknown */
    uintptr_t relative_symbol_addr; /* relative offset of the symbol from the start of the
                                    library or 0 if the library is unknown */
    char* map_name;              /* executable or library name, or NULL if unknown */
    char* symbol_name;           /* symbol name, or NULL if unknown */
    char* demangled_name;        /* demangled symbol name, or NULL if unknown */
    uintptr_t prev_size;
} backtrace_symbol_t;

/*
 * Unwinds the call stack for the current thread of execution.
 * Populates the backtrace array with the program counters from the call stack.
 * Returns the number of frames collected, or -1 if an error occurred.
 */
ssize_t unwind_backtrace(backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth);

/*
 * Unwinds the call stack for a thread within this process.
 * Populates the backtrace array with the program counters from the call stack.
 * Returns the number of frames collected, or -1 if an error occurred.
 *
 * The task is briefly suspended while the backtrace is being collected.
 */
ssize_t unwind_backtrace_thread(pid_t tid, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth);

/*
 * Unwinds the call stack of a task within a remote process using ptrace().
 * Populates the backtrace array with the program counters from the call stack.
 * Returns the number of frames collected, or -1 if an error occurred.
 */
ssize_t unwind_backtrace_ptrace(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth);

struct backtrace_context;

/*
 * Gets the symbols for each frame of a backtrace.
 * The symbols array must be big enough to hold one symbol record per frame.
 * The symbols must later be freed using free_backtrace_symbols.
 */
void get_backtrace_symbols(const struct backtrace_context* context,
        const backtrace_frame_t* backtrace, size_t frames,
        backtrace_symbol_t* backtrace_symbols);

/*
 * Gets the symbols for each frame of a backtrace from a remote process.
 * The symbols array must be big enough to hold one symbol record per frame.
 * The symbols must later be freed using free_backtrace_symbols.
 */
void get_backtrace_symbols_ptrace(const ptrace_context_t* context,
        const backtrace_frame_t* backtrace, size_t frames,
        backtrace_symbol_t* backtrace_symbols);

/*
 * Frees the storage associated with backtrace symbols.
 */
void free_backtrace_symbols(backtrace_symbol_t* backtrace_symbols, size_t frames);

enum {
    // A hint for how big to make the line buffer for format_backtrace_line
    MAX_BACKTRACE_LINE_LENGTH = 800,
};

/**
 * Formats a line from a backtrace as a zero-terminated string into the specified buffer.
 */
void format_backtrace_line(unsigned frameNumber, const backtrace_frame_t* frame,
        const backtrace_symbol_t* symbol, char* buffer, size_t bufferSize);

static bool is_elf(Elf32_Ehdr* e) {
    return (e->e_ident[EI_MAG0] == ELFMAG0 &&
            e->e_ident[EI_MAG1] == ELFMAG1 &&
            e->e_ident[EI_MAG2] == ELFMAG2 &&
            e->e_ident[EI_MAG3] == ELFMAG3);
}

// Compare function for qsort
static int qcompar(const void *a, const void *b) {
    const symbol_t* asym = (const symbol_t*)a;
    const symbol_t* bsym = (const symbol_t*)b;
    if (asym->start > bsym->start) return 1;
    if (asym->start < bsym->start) return -1;
    return 0;
}

struct bresult {
    uintptr_t addr;
    const symbol_t* left;
    const symbol_t* right;
};

// Compare function for bsearch
static int bcompar(const void *key, const void *element) {
    struct bresult* re = (struct bresult*)key;
    const symbol_t* symbol = (const symbol_t*)element;
    if (re->addr < symbol->start){ re->right = symbol; return -1;}
    if (re->addr >= symbol->end){ re->left = symbol; return 1;}    
    return 0;
}

symbol_table_t* load_symbol_table(const char *filename) {
    symbol_table_t* table = NULL;
    ALOGV("Loading symbol table from '%s'.", filename);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        goto out;
    }

    struct stat sb;
    if (fstat(fd, &sb)) {
        goto out_close;
    }

    size_t length = sb.st_size;
    char* base = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED) {
        goto out_close;
    }

    // Parse the file header
    Elf32_Ehdr *hdr = (Elf32_Ehdr*)base;
    if (!is_elf(hdr)) {
        goto out_close;
    }
    Elf32_Shdr *shdr = (Elf32_Shdr*)(base + hdr->e_shoff);

    // Search for the dynamic symbols section
    int sym_idx = -1;
    int dynsym_idx = -1;
    for (Elf32_Half i = 0; i < hdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            sym_idx = i;
        }
        if (shdr[i].sh_type == SHT_DYNSYM) {
            dynsym_idx = i;
        }
    }
    if (dynsym_idx == -1 && sym_idx == -1) {
        goto out_unmap;
    }

    table = malloc(sizeof(symbol_table_t));
    if(!table) {
        goto out_unmap;
    }
    table->num_symbols = 0;

    Elf32_Sym *dynsyms = NULL;
    int dynnumsyms = 0;
    char *dynstr = NULL;
    if (dynsym_idx != -1) {
        dynsyms = (Elf32_Sym*)(base + shdr[dynsym_idx].sh_offset);
        dynnumsyms = shdr[dynsym_idx].sh_size / shdr[dynsym_idx].sh_entsize;
        int dynstr_idx = shdr[dynsym_idx].sh_link;
        dynstr = base + shdr[dynstr_idx].sh_offset;
    }

    Elf32_Sym *syms = NULL;
    int numsyms = 0;
    char *str = NULL;
    if (sym_idx != -1) {
        syms = (Elf32_Sym*)(base + shdr[sym_idx].sh_offset);
        numsyms = shdr[sym_idx].sh_size / shdr[sym_idx].sh_entsize;
        int str_idx = shdr[sym_idx].sh_link;
        str = base + shdr[str_idx].sh_offset;
    }

    int dynsymbol_count = 0;
    if (dynsym_idx != -1) {
        // Iterate through the dynamic symbol table, and count how many symbols
        // are actually defined
        for (int i = 0; i < dynnumsyms; i++) {
            if (dynsyms[i].st_shndx != SHN_UNDEF) {
                dynsymbol_count++;
            }
        }
    }

    size_t symbol_count = 0;
    if (sym_idx != -1) {
        // Iterate through the symbol table, and count how many symbols
        // are actually defined
        for (int i = 0; i < numsyms; i++) {
            if (syms[i].st_shndx != SHN_UNDEF
                    && str[syms[i].st_name]
                    && syms[i].st_value
                    && syms[i].st_size) {
                symbol_count++;
            }
        }
    }

    // Now, create an entry in our symbol table structure for each symbol...
    table->num_symbols += symbol_count + dynsymbol_count;
    table->symbols = malloc(table->num_symbols * sizeof(symbol_t));
    if (!table->symbols) {
        free(table);
        table = NULL;
        goto out_unmap;
    }

    size_t symbol_index = 0;
    if (dynsym_idx != -1) {
        // ...and populate them
        for (int i = 0; i < dynnumsyms; i++) {
            if (dynsyms[i].st_shndx != SHN_UNDEF) {
                table->symbols[symbol_index].name = strdup(dynstr + dynsyms[i].st_name);
                table->symbols[symbol_index].start = dynsyms[i].st_value;
                table->symbols[symbol_index].end = dynsyms[i].st_value + dynsyms[i].st_size;
                ALOGV("  [%d] '%s' 0x%08x-0x%08x (DYNAMIC)",
                        symbol_index, table->symbols[symbol_index].name,
                        table->symbols[symbol_index].start, table->symbols[symbol_index].end);
                symbol_index += 1;
            }
        }
    }

    if (sym_idx != -1) {
        // ...and populate them
        for (int i = 0; i < numsyms; i++) {
            if (syms[i].st_shndx != SHN_UNDEF
                    && str[syms[i].st_name]
                    && syms[i].st_value
                    && syms[i].st_size) {
                table->symbols[symbol_index].name = strdup(str + syms[i].st_name);
                table->symbols[symbol_index].start = syms[i].st_value;
                table->symbols[symbol_index].end = syms[i].st_value + syms[i].st_size;
                ALOGV("  [%d] '%s' 0x%08x-0x%08x",
                        symbol_index, table->symbols[symbol_index].name,
                        table->symbols[symbol_index].start, table->symbols[symbol_index].end);
                symbol_index += 1;
            }
        }
    }

    // Sort the symbol table entries, so they can be bsearched later
    qsort(table->symbols, table->num_symbols, sizeof(symbol_t), qcompar);

out_unmap:
    munmap(base, length);

out_close:
    close(fd);

out:
    return table;
}

void free_symbol_table(symbol_table_t* table) {
    if (table) {
        for (size_t i = 0; i < table->num_symbols; i++) {
            free(table->symbols[i].name);
        }
        free(table->symbols);
        free(table);
    }
}

const symbol_t* find_symbol(const symbol_table_t* table, uintptr_t addr) {
    struct bresult br = {addr, NULL, NULL};
    const symbol_t* best = NULL;

    if (!table) return NULL;

    best = (const symbol_t*)bsearch(&br, table->symbols, table->num_symbols,
            sizeof(symbol_t), bcompar);

    if (best == NULL && br.left && br.right) {
        if (br.left->end < addr && br.right->start > addr) {
            return br.left;
        }
    }
    return best;
}



// 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so\n
// 012345678901234567890123456789012345678901234567890123456789
// 0         1         2         3         4         5
static map_info_t* parse_maps_line(const char* line)
{
    unsigned long int start;
    unsigned long int end;
    char permissions[5];
    int name_pos;
    if (sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d%n", &start, &end,
            permissions, &name_pos) != 3) {
        return NULL;
    }

    while (isspace(line[name_pos])) {
        name_pos += 1;
    }
    const char* name = line + name_pos;
    size_t name_len = strlen(name);
    if (name_len && name[name_len - 1] == '\n') {
        name_len -= 1;
    }

    map_info_t* mi = calloc(1, sizeof(map_info_t) + name_len + 1);
    if (mi) {
        mi->start = start;
        mi->end = end;
        mi->is_readable = strlen(permissions) == 4 && permissions[0] == 'r';
        mi->is_writable = strlen(permissions) == 4 && permissions[1] == 'w';
        mi->is_executable = strlen(permissions) == 4 && permissions[2] == 'x';
        mi->data = NULL;
        memcpy(mi->name, name, name_len);
        mi->name[name_len] = '\0';
        ALOGV("Parsed map: start=0x%08x, end=0x%08x, "
                "is_readable=%d, is_writable=%d, is_executable=%d, name=%s",
                mi->start, mi->end,
                mi->is_readable, mi->is_writable, mi->is_executable, mi->name);
    }
    return mi;
}
#define PATH_MAX 1024
map_info_t* load_map_info_list(pid_t tid) {
    char path[PATH_MAX];
    char line[1024];
    FILE* fp;
    map_info_t* milist = NULL;

    snprintf(path, PATH_MAX, "/proc/%d/maps", tid);
    fp = fopen(path, "r");
    if (fp) {
        while(fgets(line, sizeof(line), fp)) {
            map_info_t* mi = parse_maps_line(line);
            if (mi) {
                mi->next = milist;
                milist = mi;
            }
        }
        fclose(fp);
    }
    return milist;
}

void free_map_info_list(map_info_t* milist) {
    while (milist) {
        map_info_t* next = milist->next;
        free(milist);
        milist = next;
    }
}

const map_info_t* find_map_info(const map_info_t* milist, uintptr_t addr) {
    const map_info_t* mi = milist;
    while (mi && !(addr >= mi->start && addr < mi->end)) {
        mi = mi->next;
    }
    return mi;
}

bool is_readable_map(const map_info_t* milist, uintptr_t addr) {
    const map_info_t* mi = find_map_info(milist, addr);
    return mi && mi->is_readable;
}

bool is_writable_map(const map_info_t* milist, uintptr_t addr) {
    const map_info_t* mi = find_map_info(milist, addr);
    return mi && mi->is_writable;
}

bool is_executable_map(const map_info_t* milist, uintptr_t addr) {
    const map_info_t* mi = find_map_info(milist, addr);
    return mi && mi->is_executable;
}

static pthread_mutex_t g_my_map_info_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static map_info_t* g_my_map_info_list = NULL;

static const int64_t MAX_CACHE_AGE = 5 * 1000 * 1000000LL;

typedef struct {
    uint32_t refs;
    int64_t timestamp;
} my_map_info_data_t;

static int64_t now() {
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void dec_ref(map_info_t* milist, my_map_info_data_t* data) {
    if (!--data->refs) {
        ALOGV("Freed my_map_info_list %p.", milist);
        free(data);
        free_map_info_list(milist);
    }
}

map_info_t* acquire_my_map_info_list() {
    pthread_mutex_lock(&g_my_map_info_list_mutex);

    int64_t time = now();
    if (g_my_map_info_list) {
        my_map_info_data_t* data = (my_map_info_data_t*)g_my_map_info_list->data;
        int64_t age = time - data->timestamp;
        if (age >= MAX_CACHE_AGE) {
            ALOGV("Invalidated my_map_info_list %p, age=%lld.", g_my_map_info_list, age);
            dec_ref(g_my_map_info_list, data);
            g_my_map_info_list = NULL;
        } else {
            ALOGV("Reusing my_map_info_list %p, age=%lld.", g_my_map_info_list, age);
        }
    }

    if (!g_my_map_info_list) {
        my_map_info_data_t* data = (my_map_info_data_t*)malloc(sizeof(my_map_info_data_t));
        g_my_map_info_list = load_map_info_list(getpid());
        if (g_my_map_info_list) {
            ALOGV("Loaded my_map_info_list %p.", g_my_map_info_list);
            g_my_map_info_list->data = data;
            data->refs = 1;
            data->timestamp = time;
        } else {
            free(data);
        }
    }

    map_info_t* milist = g_my_map_info_list;
    if (milist) {
        my_map_info_data_t* data = (my_map_info_data_t*)g_my_map_info_list->data;
        data->refs += 1;
    }

    pthread_mutex_unlock(&g_my_map_info_list_mutex);
    return milist;
}

void release_my_map_info_list(map_info_t* milist) {
    if (milist) {
        pthread_mutex_lock(&g_my_map_info_list_mutex);

        my_map_info_data_t* data = (my_map_info_data_t*)milist->data;
        dec_ref(milist, data);

        pthread_mutex_unlock(&g_my_map_info_list_mutex);
    }
}


/* For PTRACE_GETREGS */
typedef struct {
    /* FIXME: check this definition */
    uint64_t regs[32];
    uint64_t lo;
    uint64_t hi;
    uint64_t epc;
    uint64_t badvaddr;
    uint64_t status;
    uint64_t cause;
} user_regs_struct;

/* Machine context at the time a signal was raised. */
typedef struct ucontext {
	unsigned long	  uc_flags;
	struct ucontext  *uc_link;
	stack_t		  uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t	  uc_sigmask;	/* mask last for extensibility */
} ucontext_t;

/* Unwind state. */
typedef struct {
    uint32_t sp;
    uint32_t ra;
    uint32_t pc;
    uint32_t fp;
} unwind_state_t;

uintptr_t rewind_pc_arch(const memory_t* memory, uintptr_t pc) {
    if (pc == 0)
        return pc;
    if ((pc & 1) == 0)
        return pc-8;            /* jal/bal/jalr + branch delay slot */
    return pc;
}

backtrace_frame_t* add_backtrace_entry(uintptr_t pc, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth,
        size_t* ignored_frames, size_t* returned_frames) {
    if (*ignored_frames < ignore_depth) {
        *ignored_frames += 1;

        return NULL;
    }
    if (*returned_frames >= max_depth) {
        return NULL;
    }

    backtrace_frame_t* frame = &backtrace[*returned_frames];
    frame->absolute_pc = pc;
    frame->stack_top = 0;
    frame->stack_size = 0;
    *returned_frames += 1;

    return frame;
}

static const uint32_t ELF_MAGIC = 0x7f454C46; // "ELF\0177"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif

void init_memory(memory_t* memory, const map_info_t* map_info_list) {
    memory->tid = -1;
    memory->map_info_list = map_info_list;
}

void init_memory_ptrace(memory_t* memory, pid_t tid) {
    memory->tid = tid;
    memory->map_info_list = NULL;
}

bool try_get_word(const memory_t* memory, uintptr_t ptr, uint32_t* out_value) {
    //ALOGV("try_get_word: reading word at 0x%08x", ptr);
    if (ptr & 3) {
        //ALOGV("try_get_word: invalid pointer 0x%08x", ptr);
        *out_value = 0xffffffffL;
        return false;
    }
    if (memory->tid < 0) {
        if (!is_readable_map(memory->map_info_list, ptr)) {
            //ALOGV("try_get_word: pointer 0x%08x not in a readable map", ptr);
            *out_value = 0xffffffffL;
            return false;
        }
        *out_value = *(uint32_t*)ptr;
        return true;
    } else {
        // ptrace() returns -1 and sets errno when the operation fails.
        // To disambiguate -1 from a valid result, we clear errno beforehand.
        errno = 0;
        *out_value = ptrace(PTRACE_PEEKTEXT, memory->tid, (void*)ptr, NULL);
        if (*out_value == 0xffffffffL && errno) {
            ALOGV("try_get_word: invalid pointer 0x%08x reading from tid %d, "
                    "ptrace() errno=%d", ptr, memory->tid, errno);
            return false;
        }
        return true;
    }
}

bool try_get_word_ptrace(pid_t tid, uintptr_t ptr, uint32_t* out_value) {
    memory_t memory;
    init_memory_ptrace(&memory, tid);
    return try_get_word(&memory, ptr, out_value);
}

static void load_ptrace_map_info_data(pid_t pid, map_info_t* mi) {
    if (mi->is_executable && mi->is_readable) {
        uint32_t elf_magic;
        if (try_get_word_ptrace(pid, mi->start, &elf_magic) && elf_magic == ELF_MAGIC) {
            map_info_data_t* data = (map_info_data_t*)calloc(1, sizeof(map_info_data_t));
            if (data) {
                mi->data = data;
                if (mi->name[0]) {
                    data->symbol_table = load_symbol_table(mi->name);
                }
#ifdef CORKSCREW_HAVE_ARCH
                load_ptrace_map_info_data_arch(pid, mi, data);
#endif
            }
        }
    }
}

ptrace_context_t* load_ptrace_context(pid_t pid) {
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)){
				ALOGV("ptrace(%d, %d, 0, 0) return error.",
				PTRACE_ATTACH, pid);
        return NULL;
    }    
    wait(NULL);

    ptrace_context_t* context =
            (ptrace_context_t*)calloc(1, sizeof(ptrace_context_t));

    if (context) {
        context->map_info_list = load_map_info_list(pid);
        for (map_info_t* mi = context->map_info_list; mi; mi = mi->next) {
            load_ptrace_map_info_data(pid, mi);
        }
    }
    return context;
}

static void free_ptrace_map_info_data(map_info_t* mi) {
    map_info_data_t* data = (map_info_data_t*)mi->data;
    if (data) {
        if (data->symbol_table) {
            free_symbol_table(data->symbol_table);
        }
#ifdef CORKSCREW_HAVE_ARCH
        free_ptrace_map_info_data_arch(mi, data);
#endif
        free(data);
        mi->data = NULL;
    }
}

void free_ptrace_context(int pid, ptrace_context_t* context) {
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    if (!context)
        return;

    for (map_info_t* mi = context->map_info_list; mi; mi = mi->next) {
        free_ptrace_map_info_data(mi);
    }
    free_map_info_list(context->map_info_list);
}

void find_symbol_ptrace(const ptrace_context_t* context,
        uintptr_t addr, const map_info_t** out_map_info, const symbol_t** out_symbol) {
    const map_info_t* mi = find_map_info(context->map_info_list, addr);
    const symbol_t* symbol = NULL;
    if (mi) {
        const map_info_data_t* data = (const map_info_data_t*)mi->data;
        if (data && data->symbol_table) {
            if (mi->start == 0x400000) {
                symbol = find_symbol(data->symbol_table, addr);
            } else {
                symbol = find_symbol(data->symbol_table, addr - mi->start);
            }
        }
    }
    *out_map_info = mi;
    *out_symbol = symbol;
}

static ssize_t unwind_backtrace_common(const memory_t* memory,
        const map_info_t* map_info_list,
        unwind_state_t* state, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth) {
    size_t ignored_frames = 0;
    size_t returned_frames = 0;
    bool first_ra = true;

    for (size_t index = 0; returned_frames < max_depth; index++) {

        uintptr_t pc = index ? rewind_pc_arch(memory, state->pc) : state->pc;
        backtrace_frame_t* frame;
        uintptr_t addr;
        int maxcheck = 1024;
        int stack_size = 0, ra_offset = 0;
        bool found_start = false;
        bool found_ra = false;
        int ignore_some_sp = 0;

        frame = add_backtrace_entry(pc, backtrace, ignore_depth,
                                    max_depth, &ignored_frames, &returned_frames);


        if (frame){
            frame->stack_top = state->sp;
						ALOGV("#%d: frame=%p pc=%08x sp=%08x\n",
              index, frame, frame->absolute_pc, frame->stack_top);
       }

       /* patch of some syscall instructions. */
       {
           uint32_t op1, op2;
           if (try_get_word(memory, state->pc, &op1) &&
                try_get_word(memory, state->pc - 4, &op2) &&
                op1 == 0x27bd0020 && op2 == 0x0000000c) {
               ignore_some_sp = 2;
            }
       }

       for (addr = state->pc; maxcheck-- > 0 && !found_start; addr -= 4) {
            uint32_t op;
            if (!try_get_word(memory, addr, &op))
                break;

            ALOGV("@0x%08x: 0x%08x\n", addr, op);
            switch (op & 0xffff0000) {
            case 0x23bd0000: // addi sp, imm
            case 0x27bd0000: // addiu sp, imm
                {
                    // looking for stack being decremented
                    int32_t immediate = ((((int)op) << 16) >> 16);
                    if (immediate < 0) {
                        /* patch of some syscall instructions. */
                        if (ignore_some_sp) {
                            ignore_some_sp --;
                            state->sp += -immediate;
                        } else {
                            stack_size = -immediate;
                            found_start = true;
                            ALOGV("@0x%08x: found stack adjustment=%d\n", addr, stack_size);
                        }
                    }
                }
                break;
            case 0xafbf0000: // sw ra, imm(sp)
                found_ra = true;
                ra_offset = ((((int)op) << 16) >> 16);
                ALOGV("@0x%08x: found ra offset=%d\n", addr, ra_offset);
                break;
            case 0x3c1c0000: // lui gp
                //ALOGV("@0x%08x: found function boundary\n", addr);
                //found_start = true;
                break;
            default:
                break;
            }
        }

        if (ra_offset) {
            uint32_t next_ra;
            if (!try_get_word(memory, state->sp + ra_offset, &next_ra))
                break;

            if (first_ra && (state->fp == state->ra || !next_ra)) {
                first_ra = false;
                state->pc = state->ra;
                state->fp = 0;
                continue;
            }
            first_ra = false;
            state->ra = next_ra;
            state->fp = 0;
            ALOGV("New ra: 0x%08x\n", state->ra);
        }

        if (stack_size) {
            if (frame)
                frame->stack_size = stack_size;
            state->sp += stack_size;
            ALOGV("New sp: 0x%08x\n", state->sp);
        }

        if (state->pc == state->ra && (stack_size == 0 || !found_ra)) {
            if (!found_ra && returned_frames > 0)
                returned_frames--;
            break;
        }

        if (state->ra == 0)
            break;

        state->pc = state->ra;
    }

    ALOGV("returning %d frames\n", returned_frames);

    return returned_frames;
}


ssize_t unwind_backtrace_signal_arch(siginfo_t* siginfo, void* sigcontext,
        const map_info_t* map_info_list,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    const ucontext_t* uc = (const ucontext_t*)sigcontext;

    unwind_state_t state;
    state.sp = uc->uc_mcontext.sc_regs[29];
    state.pc = uc->uc_mcontext.sc_pc;
    state.ra = uc->uc_mcontext.sc_regs[31];
    state.fp = uc->uc_mcontext.sc_regs[30];

    ALOGV("unwind_backtrace_signal_arch: "
          "ignore_depth=%d max_depth=%d pc=0x%08x sp=0x%08x ra=0x%08x\n",
          ignore_depth=0, max_depth, state.pc, state.sp, state.ra);

    memory_t memory;
    init_memory(&memory, map_info_list);
    return unwind_backtrace_common(&memory, map_info_list,
            &state, backtrace, ignore_depth, max_depth);
}

typedef struct {
    backtrace_frame_t* backtrace;
    size_t ignore_depth;
    size_t max_depth;
    size_t ignored_frames;
    size_t returned_frames;
    memory_t memory;
} backtrace_state_t;

static _Unwind_Reason_Code unwind_backtrace_callback(struct _Unwind_Context* context, void* arg) {
    backtrace_state_t* state = (backtrace_state_t*)arg;
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        // TODO: Get information about the stack layout from the _Unwind_Context.
        //       This will require a new architecture-specific function to query
        //       the appropriate registers.  Current callers of unwind_backtrace
        //       don't need this information, so we won't bother collecting it just yet.
        add_backtrace_entry(rewind_pc_arch(&state->memory, pc), state->backtrace,
                state->ignore_depth, state->max_depth,
                &state->ignored_frames, &state->returned_frames);
    }
    return state->returned_frames < state->max_depth ? _URC_NO_REASON : _URC_END_OF_STACK;
}

ssize_t unwind_backtrace(backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    ALOGV("Unwinding current thread %d.", gettid());

    map_info_t* milist = acquire_my_map_info_list();

    backtrace_state_t state;
    state.backtrace = backtrace;
    state.ignore_depth = ignore_depth;
    state.max_depth = max_depth;
    state.ignored_frames = 0;
    state.returned_frames = 0;
    init_memory(&state.memory, milist);

    _Unwind_Reason_Code rc =_Unwind_Backtrace(unwind_backtrace_callback, &state);

    release_my_map_info_list(milist);

    if (state.returned_frames) {
        return state.returned_frames;
    }
    return rc == _URC_END_OF_STACK ? 0 : -1;
}

#define DUMP_MEM_LIMIT 256
#define DUMP_DEPTH_IGNORE 0
#define DUMP_DEPTH_LIMIT 128

#define ACTION_DUMP_REGS 1
#define ACTION_DUMP_CALL 2
#define ACTION_DUMP_STACK 4

#define CAPTURE_SIG_MAX 16

#ifdef CORKSCREW_HAVE_ARCH
static const int32_t STATE_DUMPING = -1;
static const int32_t STATE_DONE = -2;
static const int32_t STATE_CANCEL = -3;

static pthread_mutex_t g_unwind_signal_mutex = PTHREAD_MUTEX_INITIALIZER;

static volatile struct backtrace_context {
    int32_t tid_state;
    map_info_t* map_info_list;
    backtrace_frame_t* backtrace;
    int ignore_depth;
    int max_depth;
    int returned_frames;
    backtrace_symbol_t* backtrace_symbols;
    char main_module_name[256];
    symbol_table_t* main_symbols;
    unsigned int dump_mem_limit;
    unsigned int action;
    unsigned int sig_count;
    unsigned int sig[CAPTURE_SIG_MAX];
} g_unwind_signal_state;

#endif

ssize_t unwind_backtrace_ptrace_arch(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {

    int ret = 0;
    int status;
    user_regs_struct regs;    
    
    if (ptrace(PTRACE_GETREGS, tid, 0, &regs)) {
				ALOGV("ptrace(%d, %d, 0, &regs) return error.",
				PTRACE_GETREGS, tid);
        return -1;
    }

    unwind_state_t state;
    state.sp = regs.regs[29];
    state.ra = regs.regs[31];
    state.pc = regs.epc;
    {
        static char* reg_name[] = {
            "zero", "at",
            "v0", "v1",
            "a0","a1","a2","a3",
            "t0","t1","t2","t3","t4","t5","t6","t7",
            "s0","s1","s2","s3","s4","s5","s6","s7",
            "t8","t9","k0","k1","gp","sp","fp/s8","ra","pc"
            };
        fprintf(stderr, "Dump regs:\n   pc: %08x status: %08x  cause: %08x badvad: %08x\n", 
                (unsigned int)regs.epc,
                (unsigned int)regs.status,
                (unsigned int)regs.cause,
                (unsigned int)regs.badvaddr);
        for (size_t i = 0; i < 32; i++) {
            fprintf(stderr, "%5s: %08x  ", reg_name[i], (unsigned int)regs.regs[i]);
            if ((i&3)==3)fprintf(stderr, "\n");
        }
    }

    ALOGV("unwind_backtrace_ptrace_arch: "
          "ignore_depth=%d max_depth=%d pc=0x%08x sp=0x%08x ra=0x%08x\n",
          ignore_depth, max_depth, state.pc, state.sp, state.ra);

    memory_t memory;
    init_memory_ptrace(&memory, tid);
    ret = unwind_backtrace_common(&memory, context->map_info_list,
            &state, backtrace, ignore_depth, max_depth);
    /***************************************/
    /*            test code                */
    /***************************************/
    if (0) {
        unsigned long spsize = 0x40;
        unsigned long long oldpc = regs.epc;
        unsigned long long oldra = regs.regs[31];
        
        regs.epc = 0x49b4b0;/*new pc*/
        regs.regs[31] = regs.epc;
        regs.regs[29] -= spsize;
        ptrace(PTRACE_SETREGS, tid, 0, &regs);        
        ptrace(PTRACE_CONT, tid, NULL, NULL);
        wait(NULL);
        regs.regs[29] += spsize;
        regs.regs[31] = oldra;
        regs.epc = oldpc;
        ptrace(PTRACE_SETREGS, tid, 0, &regs);
        ptrace(PTRACE_CONT, tid, NULL, NULL);
    }
    if (0) {
         int t=10;
         int syscall_entry = 0;
         while(t--) {
             ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
             wait(&status);
             if ( WIFEXITED(status) ) 
                 break;
             ptrace(PTRACE_GETREGS, tid, 0, &regs);
             if (1) { 
                 if (syscall_entry == 0) {  /* syscall entry */
                     syscall_entry = 1;
                     printf("call %u %u %u\n",(unsigned int)regs.regs[2],
                        (unsigned int)regs.regs[4],(unsigned int)regs.regs[5]);
                 }
                 else {  /* Syscall exit */
                     printf("return %u %u %u\n",(unsigned int)regs.regs[2],
                        (unsigned int)regs.regs[4],(unsigned int)regs.regs[5]);
                     syscall_entry = 0;
                 }
             }
        }
    }    
    /***************************************/
    return  ret;
}

ssize_t unwind_backtrace_ptrace(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
#ifdef CORKSCREW_HAVE_ARCH
    return unwind_backtrace_ptrace_arch(tid, context, backtrace, ignore_depth, max_depth);
#else
    return -1;
#endif
}

static void init_backtrace_symbol(backtrace_symbol_t* symbol, uintptr_t pc) {
    symbol->relative_pc = pc;
    symbol->relative_symbol_addr = 0;
    symbol->map_name = NULL;
    symbol->symbol_name = NULL;
    symbol->demangled_name = NULL;
    symbol->prev_size = 0;
}

char* demangle_symbol_name(const char* name) {
    // __cxa_demangle handles NULL by returning NULL
    return NULL;//__cxa_demangle(name, 0, 0, 0);
}

void get_backtrace_symbols(const struct backtrace_context* context,
        const backtrace_frame_t* backtrace, size_t frames,
        backtrace_symbol_t* backtrace_symbols) {
    map_info_t* milist = acquire_my_map_info_list();
    for (size_t i = 0; i < frames; i++) {
        const backtrace_frame_t* frame = &backtrace[i];
        backtrace_symbol_t* symbol = &backtrace_symbols[i];
        init_backtrace_symbol(symbol, frame->absolute_pc);

        const map_info_t* mi = find_map_info(milist, frame->absolute_pc);
        if (mi) {
            symbol->relative_pc = frame->absolute_pc - mi->start;
            if (mi->name[0]) {
                symbol->map_name = strdup(mi->name);
                if (mi->start == 0x400000) {
                    const symbol_t*s = find_symbol(context->main_symbols, frame->absolute_pc);

                     if (s->end < frame->absolute_pc) {
                        symbol->relative_symbol_addr = s->end;
                        symbol->prev_size = s->end - s->start;
                    } else {
                        symbol->relative_symbol_addr = s->start;
                    }
                    symbol->relative_symbol_addr -= mi->start;

                    symbol->symbol_name = strdup(s->name);
                    symbol->demangled_name = demangle_symbol_name(symbol->symbol_name);
                    continue;
                }
            }
            Dl_info info;
            if (dladdr((const void*)frame->absolute_pc, &info) && info.dli_sname) {
                symbol->relative_symbol_addr = (uintptr_t)info.dli_saddr
                        - (uintptr_t)info.dli_fbase;
                symbol->symbol_name = strdup(info.dli_sname);
                symbol->demangled_name = demangle_symbol_name(symbol->symbol_name);
            }
        }
    }
    release_my_map_info_list(milist);
}

void get_backtrace_symbols_ptrace(const ptrace_context_t* context, 
    const backtrace_frame_t* backtrace, size_t frames,
    backtrace_symbol_t* backtrace_symbols) {
    for (size_t i = 0; i < frames; i++) {
        const backtrace_frame_t* frame = &backtrace[i];
        backtrace_symbol_t* symbol = &backtrace_symbols[i];
        init_backtrace_symbol(symbol, frame->absolute_pc);
        const map_info_t* mi;        const symbol_t* s;
        find_symbol_ptrace(context, frame->absolute_pc, &mi, &s);
        if (mi) {
            symbol->relative_pc = frame->absolute_pc - mi->start;
            if (mi->name[0]) {
                symbol->map_name = strdup(mi->name);
            }
        }
        if (s) {
            uintptr_t symbol_pc = (mi->start == 0x400000) ? 
                                    frame->absolute_pc : symbol->relative_pc;

            if (s->end < symbol_pc) {
                symbol->relative_symbol_addr = s->end;
                symbol->prev_size = s->end - s->start;
            } else {
                symbol->relative_symbol_addr = s->start;
            }

            if (symbol_pc != symbol->relative_pc) {
                symbol->relative_symbol_addr -= mi->start;
            }

            symbol->symbol_name = strdup(s->name);
            symbol->demangled_name = demangle_symbol_name(symbol->symbol_name);
        }
    }
}

void free_backtrace_symbols(backtrace_symbol_t* backtrace_symbols, size_t frames) {
    for (size_t i = 0; i < frames; i++) {
        backtrace_symbol_t* symbol = &backtrace_symbols[i];
        free(symbol->map_name);
        free(symbol->symbol_name);
        free(symbol->demangled_name);
        init_backtrace_symbol(symbol, 0);
    }
}

#ifdef HAVE_BFD
static bfd* bfd_s_abfd;
static asymbol** bfd_s_symbol_list;
static int bfd_s_found;
static bool have_backtrace_symbols = false;
static const char* file_name;
static const char* function_name;
static unsigned int line_number;

static int bfd_get_backtrace_symbols(bfd *abfd, asymbol ***symbol_list_ptr)
{
	int vectorsize = bfd_get_symtab_upper_bound(abfd);

	if (vectorsize < 0) {
		fprintf (stderr, "Error while getting vector size for backtrace symbols : %s",
			bfd_errmsg(bfd_get_error()));
		return -1;
	}

	if (vectorsize == 0) {
		fprintf (stderr, "Error while getting backtrace symbols : No symbols (%s)",
			bfd_errmsg(bfd_get_error()));
		return -1;
	}

	*symbol_list_ptr = (asymbol**)malloc(vectorsize);

	if (*symbol_list_ptr == NULL) {
		fprintf (stderr, "Error while getting backtrace symbols : Cannot allocate memory");
		return -1;
	}

	vectorsize = bfd_canonicalize_symtab(abfd, *symbol_list_ptr);

	if (vectorsize < 0) {
		fprintf(stderr, "Error while getting symbol table : %s",
			bfd_errmsg(bfd_get_error()));
		return -1;
	}

	return vectorsize;
}


void bfd_init_backtrace_info()
{
	bfd_init();
	bfd_s_abfd = bfd_openr("/proc/self/exe", NULL);

	if (bfd_s_abfd == NULL) {
		fprintf(stderr, "Error while opening file for backtrace symbols : %s",
			bfd_errmsg(bfd_get_error()));
		return;
	}

	if (!(bfd_check_format_matches(bfd_s_abfd, bfd_object, NULL))) {
		fprintf (stderr, "Error while init. backtrace symbols : %s",
			bfd_errmsg (bfd_get_error ()));
		bfd_close(bfd_s_abfd);
		return;
	}

	have_backtrace_symbols = (bfd_get_backtrace_symbols(bfd_s_abfd, &bfd_s_symbol_list) > 0); 
}

void bfd_destroy_backtrace_info()
{
	if (bfd_s_abfd){
		bfd_close(bfd_s_abfd);
	}

	if (bfd_s_symbol_list){
		free(bfd_s_symbol_list);
	}		
}

void bfd_get_file_line_info(bfd *abfd, asection *section, void* _address)
{
	if (bfd_s_symbol_list == NULL) {
		return;
	}

	if (bfd_s_found) {
		return;
	}

	if ((section->flags & SEC_ALLOC) == 0) {
		return;
	}

	bfd_vma vma = bfd_get_section_vma(abfd, section);

	unsigned long address = (unsigned long)_address;
	if (address < vma) {
		return;
	}

	bfd_size_type size = bfd_section_size(abfd, section);
	if (address > (vma + size)) {
		return;
	}

	bfd_s_found =  bfd_find_nearest_line(abfd, section, bfd_s_symbol_list,
		address - vma, &file_name, &function_name, &line_number);
}
#endif

void format_backtrace_line(unsigned frameNumber, const backtrace_frame_t* frame,
        const backtrace_symbol_t* symbol, char* buffer, size_t bufferSize) {
    const char* mapName = symbol->map_name ? symbol->map_name : "<unknown>";
    const char* symbolName = symbol->demangled_name ? symbol->demangled_name : symbol->symbol_name;
    size_t fieldWidth = (bufferSize - 80) / 2;	

#ifdef HAVE_BFD
	file_name = NULL;
	function_name = NULL;
	line_number = 0;
	bfd_s_found = false ;
	char unknow_name[]="??";
	if (have_backtrace_symbols){
		bfd_map_over_sections(bfd_s_abfd, bfd_get_file_line_info, (void*)frame->absolute_pc);
		if (!bfd_s_found) {
			line_number = 0;
			file_name = unknow_name;
		}
	}else{
		line_number = 0;
		file_name = unknow_name;		
	}

	if (symbolName) {
		uint32_t pc_offset = symbol->relative_pc - symbol->relative_symbol_addr;
		if (pc_offset) {
			if (symbol->prev_size)							
				snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%.*s+%u+%u) (%s:%u)",
						frameNumber, symbol->relative_pc, fieldWidth, mapName,
						fieldWidth, symbolName, symbol->prev_size, pc_offset,
						file_name, line_number);
			else
				snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%.*s+%u) (%s:%u)",
					frameNumber, symbol->relative_pc, fieldWidth, mapName,
					fieldWidth, symbolName, pc_offset, file_name, line_number);
		} else {
			snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%.*s) (%s:%u)",
					frameNumber, symbol->relative_pc, fieldWidth, mapName,
					fieldWidth, symbolName, file_name, line_number);
		}
	} else {
		snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%s:%u)",
				frameNumber, symbol->relative_pc, fieldWidth, mapName,
				file_name, line_number);
	}
#else
	if (symbolName) {
        uint32_t pc_offset = symbol->relative_pc - symbol->relative_symbol_addr;
        if (pc_offset) {
            if (symbol->prev_size)
                snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%.*s+%u+%u)",
                        frameNumber, symbol->relative_pc, fieldWidth, mapName,
                        fieldWidth, symbolName, symbol->prev_size, pc_offset);
            else
                snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%.*s+%u)",
                    frameNumber, symbol->relative_pc, fieldWidth, mapName,
                    fieldWidth, symbolName, pc_offset);
        } else {
            snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s (%.*s)",
                    frameNumber, symbol->relative_pc, fieldWidth, mapName,
                    fieldWidth, symbolName);
        }
    } else {
        snprintf(buffer, bufferSize, "#%02d  pc %08x  %.*s",
                frameNumber, symbol->relative_pc, fieldWidth, mapName);
    }
#endif
}

static void dump_mips_regs(siginfo_t* siginfo, void* sigcontext)
{
    const ucontext_t* uc = (const ucontext_t*)sigcontext;
    static char* reg_name[] = {
        "zero", "at",
        "v0", "v1",
        "a0","a1","a2","a3",
        "t0","t1","t2","t3","t4","t5","t6","t7",
        "s0","s1","s2","s3","s4","s5","s6","s7",
        "t8","t9","k0","k1","gp","sp","fp/s8","ra","pc"
        };
    fprintf(stderr, "Dump regs:\n%5s: %08x  \n", reg_name[32], (unsigned int)uc->uc_mcontext.sc_pc);
    for (size_t i = 0; i < 32; i++) {
        fprintf(stderr, "%5s: %08x  ", reg_name[i], (unsigned int)uc->uc_mcontext.sc_regs[i]);
        if ((i&3)==3)fprintf(stderr, "\n");
    }
}

static void dump_mem_stack(siginfo_t* siginfo, void* sigcontext, map_info_t* milist, int limit) {
    const ucontext_t* uc = (const ucontext_t*)sigcontext;
    uintptr_t sp = (uintptr_t)(unsigned long)(uc->uc_mcontext.sc_regs[29]);
    const map_info_t* mi = find_map_info(milist, sp);
    fprintf(stderr, "Dump mem stack: \n (STACK: 0x%08x ~ 0x%08x SP: 0x%08x)", mi->start, mi->end, sp);
    if (mi && mi->end > sp) {
        sp &= ~3;
        if (mi->end - sp < limit)
            dump_hex((void*)sp, mi->end - sp);
        else {
            dump_hex((void*)sp, limit);
            fprintf(stderr, " 0x%08x: ......\n", sp + limit);
        }
    } else {
        sp &= ~3;
        dump_hex((void*)sp, 512);
        fprintf(stderr, " 0x%08x: ......\n", sp + 512);
    }
}

static void dump_call_stack(const backtrace_frame_t* frames, backtrace_symbol_t* backtrace_symbols,size_t frame_count) {

    fprintf(stderr, "Dump call stack:\n");

#ifdef HAVE_BFD
	if (!have_backtrace_symbols) {
		bfd_init_backtrace_info();
	}
#endif

    for (size_t i = 0; i < (size_t) frame_count; ++i) {
        char line[MAX_BACKTRACE_LINE_LENGTH];
        format_backtrace_line(i, &frames[i], &backtrace_symbols[i],
                              line, MAX_BACKTRACE_LINE_LENGTH);
        if (backtrace_symbols[i].symbol_name != NULL) {
          // get_backtrace_symbols found the symbol's name with dladdr(3).
          fprintf(stderr, "  %s\n", line);
        } else {
          // We don't have a symbol. Maybe this is a static symbol, and
          // we can look it up?
          symbol_table_t* symbols = NULL;
          if (backtrace_symbols[i].map_name != NULL) {
             symbols = load_symbol_table(backtrace_symbols[i].map_name);
          }
          const symbol_t* symbol = NULL;
          if (symbols != NULL) {
            symbol = find_symbol(symbols, frames[i].absolute_pc);
          }
          if (symbol != NULL) {
                uintptr_t offset = frames[i].absolute_pc - symbol->start;
                fprintf(stderr, "  %s (%s%+d)\n", line, symbol->name, offset);
            } else {
                fprintf(stderr, "  %s (\?\?\?)\n", line);
            }
          free_symbol_table(symbols);
        }
    }

#ifdef HAVE_BFD
	bfd_destroy_backtrace_info();
#endif
}

static void dump_signal(siginfo_t* siginfo) {
    fprintf(stderr, "Process %d Catch signal %d: \n  code = %d \terrno = %d\n", 
        gettid(),
        siginfo->si_signo,
        siginfo->si_code,
        siginfo->si_errno);
}

static void dump_hex(void*p,int len){
    int i=0;
    unsigned int*d=p;
    for (i=0;i<len;i+=4){
        if ((i&31)==0)
        fprintf(stderr,"\n %p: %08x ",&(d[i/4]), d[i/4]);
        else
        fprintf(stderr,"%08x ", d[i/4]);
    }
    fprintf(stderr,"\n");
}

static void unwind_backtrace_thread_signal_handler(int n __attribute__((unused)), siginfo_t* siginfo, void* sigcontext) {
    struct backtrace_context *bt_ctx = 
        (struct backtrace_context*)&g_unwind_signal_state;

    int action = bt_ctx->action;
    int doaction = action;
    int doexit = 0;

    if (pthread_mutex_trylock(&g_unwind_signal_mutex) == 0) {
        doexit = 1;
    }

    if (doaction == 0) {
        if (!doexit) {
            /*多个线程同时收到信号，暂时只能打印第一个。。*/
            pthread_mutex_lock(&g_unwind_signal_mutex);
        }
        doaction = ACTION_DUMP_REGS | ACTION_DUMP_STACK | ACTION_DUMP_CALL;
        bt_ctx->ignore_depth = 0;
        dump_signal(siginfo);
    }

    if (doaction & ACTION_DUMP_REGS) {
        dump_mips_regs(siginfo, sigcontext);
    }

    release_my_map_info_list(bt_ctx->map_info_list);
    bt_ctx->map_info_list = acquire_my_map_info_list();

    if (doaction & ACTION_DUMP_STACK) {
        dump_mem_stack(siginfo, sigcontext, bt_ctx->map_info_list, bt_ctx->dump_mem_limit);
    }

    if (doaction & ACTION_DUMP_CALL) {
	    bt_ctx->returned_frames = unwind_backtrace_signal_arch(
					siginfo, 
					sigcontext,
					bt_ctx->map_info_list,
					bt_ctx->backtrace,
					bt_ctx->ignore_depth,
					bt_ctx->max_depth);
        if (action == 0) {
            get_backtrace_symbols(bt_ctx,
                bt_ctx->backtrace, 
                bt_ctx->returned_frames, 
                bt_ctx->backtrace_symbols);
            dump_call_stack(bt_ctx->backtrace,
                bt_ctx->backtrace_symbols, 
                bt_ctx->returned_frames);
        }
    }

    release_my_map_info_list(bt_ctx->map_info_list);

    if (doexit) {
        fprintf(stderr,"Exiting...\n");
        exit(-1);
    }

    bt_ctx->action = 0;
    bt_ctx->max_depth = DUMP_DEPTH_LIMIT;
    bt_ctx->dump_mem_limit = DUMP_MEM_LIMIT;
    bt_ctx->ignore_depth = DUMP_DEPTH_IGNORE;
    bt_ctx->map_info_list = NULL;
}

int backtrace_init(int sigcount, unsigned int *siglist) {
    struct backtrace_context *bt_ctx = 
        (struct backtrace_context*)&g_unwind_signal_state;
    struct sigaction act;
    struct sigaction oact;

    memset(&act, 0, sizeof(act));
    memset(&oact, 0, sizeof(oact));

    act.sa_sigaction = unwind_backtrace_thread_signal_handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);

	bt_ctx->dump_mem_limit = DUMP_MEM_LIMIT;
	bt_ctx->map_info_list = NULL;
	bt_ctx->ignore_depth = DUMP_DEPTH_IGNORE;
	bt_ctx->max_depth = DUMP_DEPTH_LIMIT;
	bt_ctx->returned_frames = 0;
	bt_ctx->backtrace = (backtrace_frame_t*)
                malloc(sizeof(backtrace_frame_t) * bt_ctx->max_depth);
	memset(bt_ctx->backtrace, 0, sizeof(backtrace_frame_t) * bt_ctx->max_depth);
	bt_ctx->backtrace_symbols = (backtrace_symbol_t*) 
        malloc(sizeof(backtrace_symbol_t) * bt_ctx->max_depth);
	memset(bt_ctx->backtrace_symbols, 0, sizeof(backtrace_symbol_t) * bt_ctx->max_depth);
    readlink("/proc/self/exe", (char*)&bt_ctx->main_module_name,
        sizeof(bt_ctx->main_module_name) - 1);

    bt_ctx->main_symbols = load_symbol_table((const char*)&bt_ctx->main_module_name);

    if (sigcount > 0) {
        if (sigcount >= CAPTURE_SIG_MAX) {
            sigcount = CAPTURE_SIG_MAX - 1;
        }
        bt_ctx->sig[sigcount] = SIGSEGV;
        bt_ctx->sig_count = sigcount;
        memcpy((void*)&bt_ctx->sig, siglist, sigcount*sizeof(unsigned int));
        sigaction(siglist[sigcount], &act, &oact);
        while (sigcount--) {
            sigaction(siglist[sigcount], &act, &oact);
        }
    }
    return 0;
}

int backtrace_destory()
{
    struct backtrace_context *bt_ctx = 
        (struct backtrace_context*)&g_unwind_signal_state;
    for (size_t i = 0; i < bt_ctx->sig_count; i++) {
        signal(bt_ctx->sig[i], SIG_DFL);
    }

    if (bt_ctx->main_symbols) {
        free_symbol_table(bt_ctx->main_symbols);
        free(bt_ctx->main_symbols);
    }
    if (bt_ctx->map_info_list) {
        release_my_map_info_list(bt_ctx->map_info_list);
        bt_ctx->map_info_list = NULL;
    }
    if (bt_ctx->backtrace_symbols) {
        free_backtrace_symbols(bt_ctx->backtrace_symbols, bt_ctx->max_depth);
        free(bt_ctx->backtrace_symbols);
        bt_ctx->backtrace_symbols = NULL;
    }
    if (bt_ctx->backtrace) {
        free(bt_ctx->backtrace);
        bt_ctx->backtrace = NULL;
    }

    return 0;
}

int backtrace_dump_stack()
{
    pthread_mutex_lock(&g_unwind_signal_mutex);
    struct backtrace_context *bt_ctx = 
        (struct backtrace_context*)&g_unwind_signal_state;

    bt_ctx->returned_frames = 0;
    bt_ctx->ignore_depth = 2;
    bt_ctx->action = ACTION_DUMP_CALL;

    if (!kill(gettid(),bt_ctx->sig[bt_ctx->sig_count])) {
#if 0
            get_backtrace_symbols(bt_ctx,  
                bt_ctx->backtrace,
                bt_ctx->returned_frames,
                bt_ctx->backtrace_symbols);
            dump_call_stack(bt_ctx->backtrace, 
                bt_ctx->backtrace_symbols,
                bt_ctx->returned_frames);
#endif
    }
    
    pthread_mutex_unlock(&g_unwind_signal_mutex);
    return 0;
}

void ptrace_dump_stack(int pid)
{
    pthread_mutex_lock(&g_unwind_signal_mutex);

    struct backtrace_context *bt_ctx = 
        (struct backtrace_context*)&g_unwind_signal_state;
    ptrace_context_t *ptrace_ctx = load_ptrace_context(pid);

    if (ptrace_ctx != NULL) {
        bt_ctx->returned_frames = unwind_backtrace_ptrace(pid, 
            ptrace_ctx, bt_ctx->backtrace, 0, bt_ctx->max_depth);

        if (bt_ctx->returned_frames > 0) {
            get_backtrace_symbols_ptrace(ptrace_ctx, 
                bt_ctx->backtrace,
                bt_ctx->returned_frames,
                bt_ctx->backtrace_symbols);
            dump_call_stack(bt_ctx->backtrace,
                bt_ctx->backtrace_symbols,
                bt_ctx->returned_frames);
        }
    }
    free_ptrace_context(pid, ptrace_ctx);
    
    pthread_mutex_unlock(&g_unwind_signal_mutex);

}

unsigned long ptrace_find_symbol(ptrace_context_t *context, const char*name, int* exe) {
    unsigned long addr = 0;

    for (const map_info_t* mi = context->map_info_list; mi; mi = mi->next) {
        map_info_data_t* data = (map_info_data_t*) mi->data;
        if (data && data->symbol_table) {            
            symbol_table_t* table = data->symbol_table;
            const symbol_t* symbol = table->symbols;
            for (size_t i = 0; i < table->num_symbols; i++) {
                if (!strcmp(name, symbol->name)) {
                    addr = symbol->start;
                    *exe = 0;
                    if (mi->start != 0x400000) {
                        addr += mi->start;
                    }
                    mi = find_map_info(context->map_info_list, (uintptr_t)addr);
                    if (mi && mi->name && strcmp(mi->name, "[heap]")) {
                        *exe = mi->is_executable;
                    }
                    return addr;
                }
                symbol ++;
            }
        }
    }

    return addr;
}

int ptrace_exec_function(int pid, char*func, int a0, int a1, int a2, int a3, int argc)
{
    ptrace_context_t *ptrace_ctx = load_ptrace_context(pid);
    
    if (ptrace_ctx != NULL) {
        user_regs_struct regs;
        
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
            printf("ptrace(%d, %d, 0, &regs) return error.", PTRACE_GETREGS, pid);
            goto failed;
        } else {
            int exe = 0;
            int isfunction = 0;
            int len = strlen(func);
            unsigned int func_addr = 0x0;
            char * assign = NULL;

            while (len--) {
                if (func[len] == '(' || func[len] == ')') {
                    func[len] = '\0';
                    isfunction = 1;
                }
                if (func[len] == '=') {
                    assign = func + len + 1;
                    func[len] = '\0';
                }
            }
            if (func[0]=='@') {
                isfunction = 1;
                func++;
            }

            func_addr = ptrace_find_symbol(ptrace_ctx, func, &exe);

            if (func_addr && !exe) {
                if (assign) {
                    const map_info_t* mi = find_map_info(ptrace_ctx->map_info_list, func_addr);
                    if (mi && mi->is_writable) {
                        if (ptrace(PTRACE_POKEDATA, pid, func_addr, strtol(assign,NULL,0))) {
                            printf("ASSIGN: write %s failed\n", func);
                            goto failed;
                        }
                        printf("ASSIGN: assign %s = %08x\n", func, (unsigned int)strtol(assign,NULL,0));
                        goto success;
                    } else {
                        printf("ASSIGN: address %08x not writeable\n", func_addr);
                        goto failed;
                    }
                } else if (isfunction || argc > 0) {
                    if (!try_get_word_ptrace(pid, func_addr,  &func_addr)) {
                        goto failed;
                    }

                    if (func_addr) {                        
                        const map_info_t* mi = find_map_info(ptrace_ctx->map_info_list, func_addr);
                        printf("POINTER: pointer %s value = %08x.\n", func, func_addr);
                        if (mi && mi->is_executable) {
                            exe = 1;
                        } else {
                            printf("EXECUTE: function %s = %08x not executable.\n", func, func_addr);
                            goto failed;
                        }
                    } else {
                        printf("EXECUTE: function %s = %08x not executable.\n", func, func_addr);
                        goto failed;
                    }
                } else {
                    if (!try_get_word_ptrace(pid, func_addr,  &func_addr)) {
                        goto failed;
                    }
                    printf("DISPLAY: %s = %08x\n", func, func_addr);
                    goto success;
                }
            }
            
            if (exe && func_addr) {
                unsigned long spsize = 0x100; /* more safe if bigger value*/
                user_regs_struct newregs = regs;
                unsigned long new_sp = regs.regs[29] - spsize;
                unsigned long new_pc = new_sp + 16;

                if (ptrace(PTRACE_POKETEXT, pid, new_pc + 0,  0x0320f809) ||/* jalr t9 */
                    ptrace(PTRACE_POKETEXT, pid, new_pc + 4,  0x00000000) ||/* nop */
                    ptrace(PTRACE_POKETEXT, pid, new_pc + 8,  0x0000000d) ||/* break */
                    ptrace(PTRACE_POKETEXT, pid, new_pc + 12,  0x00000000)) {
                        goto failed;
                }

                newregs.epc = new_pc;/*pc*/
                newregs.regs[2] = 0; /*v0*/
                newregs.regs[4] = a0;/*a0*/
                newregs.regs[5] = a1;/*a1*/
                newregs.regs[6] = a2;/*a2*/
                newregs.regs[7] = a3;/*a3*/
                newregs.regs[25] = func_addr;/*t9*/
                newregs.regs[31] = new_pc;/*ra*/
                newregs.regs[29] = new_sp;/*sp*/

                printf("EXECUTE: function '%s' address = %08x.\n\n", func, func_addr);

                if (ptrace(PTRACE_SETREGS, pid, 0, &newregs) ||
                    ptrace(PTRACE_CONT, pid, NULL, NULL)) {
                  goto failed;
                }

                do {
                    wait(NULL);
                    ptrace(PTRACE_GETREGS, pid, 0, &newregs);
                    //printf("epc = %08x\n", ((unsigned int)newregs.epc));
                } while (((unsigned int)newregs.epc) != new_pc + 8);

                ptrace(PTRACE_SETREGS, pid, 0, &regs);
                ptrace(PTRACE_CONT, pid, NULL, NULL);

                printf("\n\nEXECUTE: %s() return %08x\n", func, (unsigned int)newregs.regs[2]);
            } else {
                printf("EXECUTE: function %s not found.\n", func);
                goto failed;
            }
        }
    } else {
        printf("Attaching process pid=%d failed!\n", pid);
    }
    
success:
    free_ptrace_context(pid, ptrace_ctx);    
    return 0;

failed:
    free_ptrace_context(pid, ptrace_ctx);
    return -1;
}

#if 0
void do_backtrace() {
  ssize_t frame_count = 0;
  const size_t MAX_DEPTH = 32;
  backtrace_frame_t* frames = (backtrace_frame_t*) malloc(sizeof(backtrace_frame_t) * MAX_DEPTH);
	map_info_t* milist = acquire_my_map_info_list();
  if(0){
		frame_count = unwind_backtrace(frames, 0, MAX_DEPTH);
  }
	if(0){
		ptrace_context_t ptrace_ctx;
		ptrace_ctx.map_info_list = milist;
		frame_count = unwind_backtrace_ptrace(gettid(), &ptrace_ctx, frames, 0, MAX_DEPTH);
  }
  if (1) {
    struct sigaction act;
    struct sigaction oact;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = unwind_backtrace_thread_signal_handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);

		g_unwind_signal_state.map_info_list = milist;
		g_unwind_signal_state.backtrace = frames;
		g_unwind_signal_state.ignore_depth = 1;
		g_unwind_signal_state.max_depth = MAX_DEPTH;
		g_unwind_signal_state.returned_frames = 0;

		sigaction(SIGSEGV, &act, &oact);
		kill(gettid(),SIGSEGV);
		
		frame_count = g_unwind_signal_state.returned_frames;
  }
	
  fprintf(stderr, "frame_count = %d\n", (int) frame_count);

  backtrace_symbol_t* backtrace_symbols = (backtrace_symbol_t*) malloc(sizeof(backtrace_symbol_t) * frame_count);
  get_backtrace_symbols(frames, frame_count, backtrace_symbols, NULL);

  for (size_t i = 0; i < (size_t) frame_count; ++i) {
    char line[MAX_BACKTRACE_LINE_LENGTH];
    format_backtrace_line(i, &frames[i], &backtrace_symbols[i],
                          line, MAX_BACKTRACE_LINE_LENGTH);
    if (backtrace_symbols[i].symbol_name != NULL) {
      // get_backtrace_symbols found the symbol's name with dladdr(3).
      fprintf(stderr, "  %s\n", line);
    } else {
      // We don't have a symbol. Maybe this is a static symbol, and
      // we can look it up?
      symbol_table_t* symbols = NULL;
      if (backtrace_symbols[i].map_name != NULL) {
        symbols = load_symbol_table(backtrace_symbols[i].map_name);
      }
      const symbol_t* symbol = NULL;
      if (symbols != NULL) {
        symbol = find_symbol(symbols, frames[i].absolute_pc);
      }
      if (symbol != NULL) {
        uintptr_t offset = frames[i].absolute_pc - symbol->start;
        fprintf(stderr, "  %s (%s%+d)\n", line, symbol->name, offset);
      } else {
        fprintf(stderr, "  %s (\?\?\?)\n", line);
      }
      free_symbol_table(symbols);
    }
  }
  
	release_my_map_info_list(milist);
  free_backtrace_symbols(backtrace_symbols, frame_count);
  free(backtrace_symbols);
  free(frames);
}


int a;
__attribute__ ((noinline)) void g() {
  fprintf(stderr, "g()\n");
  backtrace_dump_stack();
  memcpy((void*)&a,(void*)&a,4);
  sleep(3);
  memcpy((void*)7,(void*)1000,1000);
}

__attribute__ ((noinline)) int f(int i) {
  fprintf(stderr, "f(%i)\n", i);
  if (i == 0) {
    g();
    return 0;
  }
  return f(i - 1);
}

int do_bt_test() {
  return f(5);
}

void dump_reg(void*p,int len){
    int i=0;
    unsigned int*d=p;
    for (i=0;i<len;i+=4){
        if ((i&15)==0)
        fprintf(stderr,"\n %p: %08x ",&(d[i/4]), d[i/4]);
        else
        fprintf(stderr,"%08x ", d[i/4]);
    }
    fprintf(stderr,"\n");
}

#endif

#define SIG32 77 //"Real-time event 32"
#define SIG33 45 //"Real-time event 33"
#define SIG34 46 //"Real-time event 34"

__attribute((constructor)) void backtrace_before_main()  
{
    unsigned int sigs[] = {SIGSEGV, SIGILL, SIGINT, SIGTRAP, SIGFPE, SIGBUS, SIGSYS, SIGPIPE, SIGABRT, SIG32, SIG33, SIG34};
	backtrace_init(sizeof(sigs)/sizeof(unsigned int), sigs);
}  

__attribute((destructor)) void backtrace_after_main()  
{
    backtrace_destory();
}
#endif
