/*
 *      ____          _ _____     _   
 *     |  _ \ ___  __| |  ___|_ _| |_ 
 * --- | |_) / _ \/ _` | |_ / _` | __| ---------------------->
 *     |  _ <  __/ (_| |  _| (_| | |_ 
 *     |_| \_\___|\__,_|_|  \__,_|\__| BINARY HARDENING SYSTEM
 *
 * Copyright (C) 2022 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "stdlib.c"

#define REDFAT_NO_INCLUDE   1
#include "e9loader.h"
#include "redfat.h"
#include "redfat-rt.h"

#define REDFAT_NOINLINE         __attribute__((__noinline__))
#define REDFAT_NORETURN         __attribute__((__noreturn__))

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define MAGENTA "\33[35m"
#define WHITE   "\33[0m"

#define REDFAT_MESSAGE_LOG          0
#define REDFAT_MESSAGE_WARNING      1
#define REDFAT_MESSAGE_ERROR        2

static bool redfat_isatty         = false;
static bool redfat_disabled       = false;
static bool redfat_dso            = false;
static mutex_t redfat_print_mutex = MUTEX_INITIALIZER;

extern uint8_t __executable_start[];
#define redfat_config                                               \
    ((const struct redfat *)(__executable_start - REDFAT_PAGE_SIZE))

/*
 * Print the redfat banner.
 */
static REDFAT_NOINLINE void redfat_print_banner(const char *color)
{
    fprintf_unlocked(stderr, "%s"
        "_|_|_|    _|_|_|_|  _|_|_|        _|_|              _|\n"
        "_|    _|  _|        _|    _|    _|        _|_|_|  _|_|_|_|\n"
        "_|_|_|    _|_|_|    _|    _|  _|_|_|_|  _|    _|    _|\n"
        "_|    _|  _|        _|    _|    _|      _|    _|    _|\n"
        "_|    _|  _|_|_|_|  _|_|_|      _|        _|_|_|      _|_|%s\n"
        "\n",
        (redfat_isatty? color: ""), (redfat_isatty? WHITE: ""));
}

/*
 * Print an error or warning.
 */
static REDFAT_NOINLINE void redfat_message(const char *format, int msg,
    va_list ap)
{
    if (mutex_lock(&redfat_print_mutex) < 0)
        return;

    if (msg != REDFAT_MESSAGE_LOG)
        redfat_print_banner((msg == REDFAT_MESSAGE_ERROR? RED: YELLOW));
    const char *color = MAGENTA, *type = "LOG";
    switch (msg)
    {
        case REDFAT_MESSAGE_WARNING:
            color = YELLOW; type = "WARNING"; break;
        case REDFAT_MESSAGE_ERROR:
            color = RED; type = "ERROR"; break;
        default:
            break;
    }
    fprintf_unlocked(stderr, "%sREDFAT %s%s: ",
        (redfat_isatty? color: ""),
        type,
        (redfat_isatty? WHITE: ""));
    vfprintf_unlocked(stderr, format, ap);
    fputc_unlocked('\n', stderr);
    fflush_unlocked(stderr);

    mutex_unlock(&redfat_print_mutex);
}

/*
 * Print an error and exit.
 */
#define redfat_error    _redfat_error
static REDFAT_NOINLINE REDFAT_NORETURN void redfat_error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    redfat_message(format, REDFAT_MESSAGE_ERROR, ap);
    va_end(ap);
    abort();
}

/*
 * Print a warning.
 */
#define redfat_warning  _redfat_warning
static REDFAT_NOINLINE void redfat_warning(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    redfat_message(format, REDFAT_MESSAGE_WARNING, ap);
    va_end(ap);
}

/*
 * Print a log message.
 */
#define _redfat_log     _redfat_log
static REDFAT_NOINLINE void redfat_log(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    redfat_message(format, REDFAT_MESSAGE_LOG, ap);
    va_end(ap);
}

/****************************************************************/
/* ALLOWLIST                                                    */
/****************************************************************/

struct ALLOWTREE
{
    void *root;
};
struct ALLOWNODE
{
    const void *addr;
    int allow;          // 0 = false detection; do not allow
                        // 1 = heap ptr observed; no false detection
                        // 2 = no heap ptr observed
};

static mutex_t allowlist_mutex  = MUTEX_INITIALIZER;
static bool    allowlist_inited = false;
static FILE   *allowlist_stream = NULL;
static ALLOWTREE allowlist_root = {NULL};

static int allow_compare(const void *n, const void *m)
{
    const ALLOWNODE *N = (ALLOWNODE *)n, *M = (ALLOWNODE *)m;
    if (N->addr < M->addr)
        return -1;
    if (N->addr > M->addr)
        return 1;
    return 0;
}

static inline ALLOWNODE *allow_find(const ALLOWNODE *key)
{
    void *node = tfind(key, &allowlist_root.root, allow_compare);
    return (node == NULL? NULL: *(ALLOWNODE **)node);
}
#define allow_insert(key)                   \
    (void)tsearch((key), &allowlist_root.root, allow_compare)
#define allow_walk(action)                  \
    twalk(allowlist_root.root, (action))

#define ALLOWLIST_FILENAME                  \
    (redfat_config->filename.allowlist)

/*
 * Lowfat allow-list parse.
 */
static void redfat_allowlist_read(FILE *file, const char *filename)
{
    while (true)
    {
        char c;
        while (isspace(c = getc(file)) && c != EOF && c != '#')
            ;
        switch (c)
        {
            case EOF:
                return;
            case '#':
                while ((c = getc(file)) != '\n' && c != EOF)
                    ;
                continue;
            default:
                break;
        }
        char buf[32];
        buf[0] = c;
        unsigned i;
        for (i = 1; i < sizeof(buf)-1; i++)
        {
            buf[i] = getc(file);
            if (buf[i] == EOF)
                return;
            if (isspace(buf[i]))
                break;
        }
        buf[i] = '\0';
        const void *addr = (const void *)strtoull(buf, NULL, 0);
        while (isspace(c = getc(file)) && c != EOF)
            ;
        intptr_t allow = 0;
        switch (c)
        {
            case '0': case '1': case '2': case '3':
                allow = c - '0';
                break;
            default:
                redfat_error("failed to parse allow-list \"%s\"",
                    filename);

        }
        ALLOWNODE *node = (ALLOWNODE *)malloc(sizeof(ALLOWNODE));
        if (node == NULL)
            return;
        node->addr  = addr;
        node->allow = allow;
        allow_insert(node);
    }
}

/*
 * Lowfat allow-list write.
 */
static FILE *allowlist_write_stream = NULL;
static void redfat_allowlist_write(const void *nodep, const VISIT which,
    const int depth)
{
    switch (which)
    {
        case postorder: case leaf:
            break;
        default:
            return;
    }
    const ALLOWNODE *node = *(ALLOWNODE **)nodep;
    fprintf(allowlist_write_stream, "%p %d\n", node->addr, (int)node->allow);
}

/*
 * Initialize the allowlist.
 */
static void redfat_allowlist_init(void)
{
    const char *allowlist_filename = ALLOWLIST_FILENAME;
    fprintf(stderr, "REDFAT LOG: reading allow-list \"%s\"\n",
        allowlist_filename);
    int fd = open(allowlist_filename, O_RDWR | O_CREAT | O_CLOEXEC,
        S_IRUSR | S_IWUSR);
    if (fd < 0)
        redfat_error("failed to open allow-list \"%s\": %s",
            allowlist_filename, strerror(errno));
    if (flock(fd, LOCK_EX) < 0)
        redfat_error("failed to lock allow-list \"%s\": %s",
            allowlist_filename, strerror(errno));
    FILE *stream = fdopen(fd, "r+");
    if (stream == NULL)
        redfat_error("failed to create allow-list stream \"%s\": %s",
            allowlist_filename, strerror(errno));
    redfat_allowlist_read(stream, allowlist_filename);
    allowlist_stream = stream;
    allowlist_inited = true;
}

/*
 * Finalize the allowlist.
 */
static void redfat_allowlist_fini(void)
{
    if (allowlist_stream == NULL)
        return;

    const char *allowlist_filename = ALLOWLIST_FILENAME;
    fprintf(stderr, "REDFAT LOG: writing allow-list \"%s\"\n",
        allowlist_filename);
    FILE *stream = allowlist_stream;
    if (fseek(stream, 0, SEEK_SET) < 0)
        redfat_error("failed to rewind allow-list stream \"%s\": %s",
            allowlist_filename, strerror(errno));
    if (ftruncate(fileno(stream), 0) < 0)
        redfat_error("failed to trunacte allow-list stream \"%s\": %s",
            allowlist_filename, strerror(errno));
    fputs("# RedFat ALLOWLIST\n", stream);
    fputs("# 0 = Redzone-only\n", stream);
    fputs("# 1 = Lowfat+Redzone\n", stream);
    fputs("# 2 = Nonfat\n", stream);
    fputs("# 3 = Not reached\n\n", stream);
    allowlist_write_stream = stream;
    allow_walk(redfat_allowlist_write);
    fclose(stream);
}

/*
 * Redfat base operation.
 */
static void *redfat_base(const void *ptr_base, const void *ptr_access)
{
    /*
     * This differs from redfat_base() in that ptr_access is used to get the
     * index.  This approach is robust in the case where ptr_base is a
     * garbage pointer value, which can happen (for example) in memory access
     * where the base/index registers are swapped.
     */
    size_t idx = redfat_index(ptr_access);
    unsigned __int128 tmp = (unsigned __int128)_REDFAT_MAGICS[idx] *
        (unsigned __int128)(uintptr_t)ptr_base;
    size_t objidx = (size_t)(tmp >> 64);
    size_t *base = (size_t *)(objidx * _REDFAT_SIZES[idx]);
    return base;
}

/*
 * Lowfat allow-list generation.
 */
void redfat_allowlist_check(const void *instr_addr, intptr_t ptr_base_0,
    const void *ptr_access, size_t access_size, const char *asm_str)
{
    const void *ptr_base = (const void *)ptr_base_0;

    if (mutex_lock(&allowlist_mutex) < 0)
        return;

    if (!allowlist_inited)
        redfat_allowlist_init();

    size_t *base = (size_t *)redfat_base(ptr_base, ptr_access);
    int8_t allow = ALLOW_NONFAT;
    if (base != NULL)
    {
        allow = ALLOW_LOWFAT;
        size_t object_size = *base;
        const uint8_t *lb_object = ((const uint8_t *)base) + 16;
        const uint8_t *ub_object = lb_object + object_size;

        const uint8_t *lb_access = (const uint8_t *)ptr_access;
        const uint8_t *ub_access = lb_access + access_size;

        if (lb_access < lb_object || ub_access > ub_object)
        {
            ALLOWNODE key;
            key.addr = instr_addr;
            ALLOWNODE *node = allow_find(&key);
            if (node == NULL || node->allow != 0)
            {
                redfat_warning("potential false-postive detected!\n"
                    "\tbase        = %p\n"
                    "\tobject      = %p..%p [%zu]\n"
                    "\taccess      = %p..%p [%zu]\n"
                    "\tinstruction = %s%s%s [%s%p%s]\n",
                    ptr_base,
                    lb_object,
                    ub_object,
                    object_size,
                    lb_access,
                    ub_access,
                    access_size,
                    (redfat_isatty? GREEN: ""),
                    asm_str,
                    (redfat_isatty? WHITE: ""),
                    (redfat_isatty? YELLOW: ""),
                    instr_addr,
                    (redfat_isatty? WHITE: ""));
            }
            allow = ALLOW_REDZONE;
        }
    }

    ALLOWNODE key;
    key.addr = instr_addr;

    ALLOWNODE *node = allow_find(&key);
    if (node == NULL)
    {
        redfat_log("reached %p (%d) [%s]", instr_addr, allow,
            redfat_config->filename.allowlist);
        node = (ALLOWNODE *)malloc(sizeof(ALLOWNODE));
        if (node == NULL)
            redfat_error("failed to allocate allowlist node: %s",
                strerror(errno));
        node->addr  = instr_addr;
        node->allow = allow;
        allow_insert(node);
    }
    else if (allow < node->allow)
    {
        redfat_log("reached %p (%d->%d) [%s]", instr_addr, node->allow,
            allow, redfat_config->filename.allowlist);
        node->allow = allow;
    }
    
    if (mutex_unlock(&allowlist_mutex) < 0)
        return;
}

/****************************************************************/
/* DEBUG                                                        */
/****************************************************************/

struct DEBUGTREE
{
    void *root;
};
static mutex_t debug_mutex  = MUTEX_INITIALIZER;
static DEBUGTREE debug_root = {NULL};

static int debug_compare(const void *n, const void *m)
{
    if (n < m)
        return -1;
    if (n > m)
        return 1;
    return 0;
}

#define debug_find(key)             \
	(tfind((key), &debug_root.root, debug_compare) != NULL)
#define debug_insert(key)           \
    (void)tsearch((key), &debug_root.root, debug_compare)

/*
 * Lowfat debug check.
 */
void redfat_debug_check(const void *addr, intptr_t ptr_base_0,
    const void *ptr_access, size_t size_access, const char *asm_str)
{
    const void *ptr_base = (const void *)ptr_base_0;
    if (ptr_base == NULL)
        ptr_base = ptr_access;
    size_t *base = (size_t *)redfat_base(ptr_base, ptr_access);
    if (base == NULL)
        return;
    size_t size = *base;
    ssize_t diff_lb = (const uint8_t *)ptr_access -
        ((const uint8_t *)base + REDFAT_REDZONE_SIZE);
    ssize_t diff_ub = (const uint8_t *)ptr_access + size_access -
        ((const uint8_t *)base + REDFAT_REDZONE_SIZE);
    if ((size_t)diff_lb > size || (size_t)diff_ub > size ||
            size > redfat_size(ptr_access))
    {
        if (mutex_lock(&debug_mutex) == 0)
        {
            if (debug_find(addr))
            {
                // Memory error already reported, so ignore.
                mutex_unlock(&debug_mutex);
                return;
            }
            debug_insert(addr);
            mutex_unlock(&debug_mutex);
        }

        const uint8_t *access_base   =
            (const uint8_t *)redfat_base(ptr_access);
        size_t access_size           = *(const size_t *)access_base;
        bool access_free             = (access_size == 0x0);
        access_size                  =
            (access_free? redfat_size(ptr_access): access_size);
        const uint8_t *access_obj_lb = access_base + REDFAT_REDZONE_SIZE;
        const uint8_t *access_obj_ub = access_obj_lb + access_size;

        const uint8_t *base_base     =
            (const uint8_t *)redfat_base(ptr_base, ptr_access);
        size_t base_size             = *(const size_t *)base_base;
        bool base_free               = (base_size == 0x0);
        base_size                    =
            (base_free? redfat_size(ptr_base): base_size);
        const uint8_t *base_obj_lb   = base_base + REDFAT_REDZONE_SIZE;
        const uint8_t *base_obj_ub   = base_obj_lb + base_size;

        const char *kind = "out-of-bounds";
        if (access_free && base_free)
            kind = "use-after-free";
        else if (size > redfat_size(ptr_access))
            kind = "size-metadata-corruption";
 
        redfat_warning("%s error detected!\n"
            "\tinstruction = %s%s%s [%s%p%s]\n"
            "\taccess.ptr  = %p\n"
            "\taccess.size = %zu\n"
            "\taccess.obj  = [%+ld..%+ld]%s\n"
            "\tbase.ptr    = %p (%+ld)\n"
            "\tbase.obj    = [%+ld..%+ld]%s\n",
            kind,
            (redfat_isatty? GREEN: ""),
            asm_str,
            (redfat_isatty? WHITE: ""),
            (redfat_isatty? YELLOW: ""),
            addr,
            (redfat_isatty? WHITE: ""),
            ptr_access,
            size_access,
            access_obj_lb - (const uint8_t *)ptr_access,
            access_obj_ub - (const uint8_t *)ptr_access,
            (access_free? " (free)": ""),
            ptr_base,
            (const uint8_t *)ptr_base - (const uint8_t *)ptr_access,
            base_obj_lb - (const uint8_t *)ptr_access,
            base_obj_ub - (const uint8_t *)ptr_access,
            (base_free? " (free)": ""));
    }
}
namespace std
{
    typedef decltype(nullptr) nullptr_t;
}
void redfat_debug_check(const void *addr, std::nullptr_t ptr_base,
    const void *ptr_access, size_t size_access, const char *asm_str)
{
    redfat_debug_check(addr, (intptr_t)0x0, ptr_access, size_access, asm_str);
}

/*
 * Lowfat error handler.
 */
static void redfat_sigaction_handler(int sig, siginfo_t *info, void *context)
{
    redfat_error("out-of-bounds/use-after-free error detected!");
}

/*
 * RedFat entry.
 */
extern "C"
{

void init(int argc, char **argv, char **envp, void *dynamic,
    const struct e9_config_s *config)
{
    environ = envp;
    redfat_disabled = (getenv("REDFAT_DISABLE") != NULL);
    redfat_isatty = isatty(STDERR_FILENO);
    if ((config->flags & E9_FLAG_EXE) == 0)
        redfat_dso = true;

    const intptr_t SIZES   = 0x100000;
    const intptr_t MAGICS  = 0x180000;
    const size_t   SIZE    = 0x10000 * sizeof(uint64_t);

    // Check if we need profiling, and if so, map the profiling memory.
    intptr_t r;
    if ((redfat_config->flags & REDFAT_FLAG_PROFILE) != 0 &&
        msync((void *)REDFAT_PROFILE, REDFAT_PAGE_SIZE, MS_ASYNC) != 0 &&
        errno == ENOMEM)
    {
        r = (intptr_t)mmap((void *)REDFAT_PROFILE, REDFAT_PAGE_SIZE,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0);
        if (r != REDFAT_PROFILE)
            goto mmap_failed;
    }

    // Check if MAGICS is already mapped.  If it is, then we are running
    // with libredfat.so, so we can return.  For this we use msync().
    if (msync((void *)MAGICS, REDFAT_PAGE_SIZE, MS_ASYNC) == 0 ||
            errno != ENOMEM)
    {
        if (redfat_dso || redfat_disabled)
            return;
        struct sigaction action;
        memset(&action, 0x0, sizeof(action));
        action.sa_sigaction  = redfat_sigaction_handler;
        action.sa_flags     |= SA_SIGINFO;
        if (sigaction(SIGILL, &action, NULL) < 0)
            redfat_warning("failed to set SIGILL handler: %s",
                strerror(errno));
        return;
    }

    // We are not running with libredfat.so.  Warn the user, and map
    // dummy tables so the instrumentation will not crash.
    if (!redfat_disabled && !redfat_dso)
        redfat_error("the REDFAT runtime (%slibredfat.so%s) has not been "
            "LD_PRELOAD'ed\n"
            "              (define REDFAT_DISABLE=1 to disable this error "
                "message)",
            (redfat_isatty? GREEN: ""), (redfat_isatty? WHITE: ""));
    r = (intptr_t)mmap((void *)MAGICS, SIZE, PROT_READ,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (r != MAGICS)
    {
mmap_failed:
        redfat_error("call to mmap() failed during initialization: %s",
            strerror(errno));
    }
    r = (intptr_t)mmap((void *)SIZES, SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (r != SIZES)
        goto mmap_failed;
    memset((void *)SIZES, 0xFF, SIZE);
    if (mprotect((void *)SIZES, SIZE, PROT_READ) < 0)
        redfat_error("call to mprotect() failed during initialization: %s",
            strerror(errno));
}

/*
 * RedFat exit.
 */
void fini(void)
{
    redfat_allowlist_fini();

    if ((redfat_config->flags & REDFAT_FLAG_PROFILE) == 0 || redfat_disabled ||
            redfat_dso)
        return;
    ssize_t maxrss = -1;
    ssize_t utime  = -1;
    ssize_t stime  = 0;
    struct rusage buf;
    if (getrusage(RUSAGE_SELF, &buf) == 0)
    {
        maxrss = buf.ru_maxrss;
        utime = 1000 * buf.ru_utime.tv_sec + buf.ru_utime.tv_usec / 1000;
        stime = 1000 * buf.ru_stime.tv_sec + buf.ru_stime.tv_usec / 1000;
    }

    const size_t *profile = (const size_t *)REDFAT_PROFILE;
    redfat_print_banner(MAGENTA);
    fprintf(stderr, "%sREDFAT STATS%s:\n\n",
		(redfat_isatty? RED: ""), (redfat_isatty? WHITE: ""));
    fprintf(stderr, "total.time     = %zdms\n", utime + stime);
    fprintf(stderr, "total.maxrss   = %zdkB\n", maxrss);
    fprintf(stderr, "redzone.checks = %zu (%zureads + %zuwrites)\n",
        profile[REDFAT_PROFILE_REDZONE_READ_UNOPTIMIZED_CHECKS] +
        profile[REDFAT_PROFILE_REDZONE_WRITE_UNOPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_REDZONE_READ_UNOPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_REDZONE_WRITE_UNOPTIMIZED_CHECKS]);
    fprintf(stderr, "   (optimized) = %zu (%zureads + %zuwrites)\n",
        profile[REDFAT_PROFILE_REDZONE_READ_OPTIMIZED_CHECKS] +
        profile[REDFAT_PROFILE_REDZONE_WRITE_OPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_REDZONE_READ_OPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_REDZONE_WRITE_OPTIMIZED_CHECKS]);
    fprintf(stderr, "        (heap) = %zu (%zureads + %zuwrites)\n",
        profile[REDFAT_PROFILE_REDZONE_READ_NONLEGACY_CHECKS] +
        profile[REDFAT_PROFILE_REDZONE_WRITE_NONLEGACY_CHECKS],
        profile[REDFAT_PROFILE_REDZONE_READ_NONLEGACY_CHECKS],
        profile[REDFAT_PROFILE_REDZONE_WRITE_NONLEGACY_CHECKS]);
    fprintf(stderr, "lowfat.checks  = %zu (%zureads + %zuwrites)\n",
        profile[REDFAT_PROFILE_LOWFAT_READ_UNOPTIMIZED_CHECKS] +
        profile[REDFAT_PROFILE_LOWFAT_WRITE_UNOPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_LOWFAT_READ_UNOPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_LOWFAT_WRITE_UNOPTIMIZED_CHECKS]);
    fprintf(stderr, "   (optimized) = %zu (%zureads + %zuwrites)\n",
        profile[REDFAT_PROFILE_LOWFAT_READ_OPTIMIZED_CHECKS] +
        profile[REDFAT_PROFILE_LOWFAT_WRITE_OPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_LOWFAT_READ_OPTIMIZED_CHECKS],
        profile[REDFAT_PROFILE_LOWFAT_WRITE_OPTIMIZED_CHECKS]);
    fprintf(stderr, "        (heap) = %zu (%zureads + %zuwrites)\n\n",
        profile[REDFAT_PROFILE_LOWFAT_READ_NONLEGACY_CHECKS] +
        profile[REDFAT_PROFILE_LOWFAT_WRITE_NONLEGACY_CHECKS],
        profile[REDFAT_PROFILE_LOWFAT_READ_NONLEGACY_CHECKS],
        profile[REDFAT_PROFILE_LOWFAT_WRITE_NONLEGACY_CHECKS]);
}

}   // extern "C"
