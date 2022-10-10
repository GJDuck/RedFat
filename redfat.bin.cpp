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

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <elf.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#define STRING(s)               STRING_2(s)
#define STRING_2(s)             #s

static bool option_is_tty = false;

/*
 * Report an error and exit.
 */
void __attribute__((noreturn)) error(const char *msg, ...)
{
    fprintf(stderr, "%serror%s  : ",
        (option_is_tty? "\33[31m": ""),
        (option_is_tty? "\33[0m" : ""));
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);
    exit(EXIT_FAILURE);
}

/*
 * Report a warning.
 */
void warning(const char *msg, ...)
{
    fprintf(stderr, "%swarning%s : ",
        (option_is_tty? "\33[33m": ""),
        (option_is_tty? "\33[0m" : ""));
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);
}

/*
 * Get the executable path.
 */
static void getExePath(std::string &path)
{
    char buf[PATH_MAX+1];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len < 0 || len > sizeof(buf)-1)
        error("failed to read executable path: %s", strerror(errno));
    buf[len] = '\0';
    char *dir = dirname(buf);
    path += dir;
}

enum Option
{
    OPTION_XLOWFAT = 1000,
    OPTION_XREADS,
    OPTION_XWRITES,
    OPTION_XSTACK,
    OPTION_XFRAME,
    OPTION_XGLOBALS,
    OPTION_XSIZE,
    OPTION_XADJUST,
    OPTION_XDEBUG,
    OPTION_XALLOWLIST_GEN,
    OPTION_XALLOWLIST_USE,
    OPTION_XALLOWLIST_MODE,
    OPTION_OELIM,
    OPTION_OBATCH,
    OPTION_OMERGE,
    OPTION_OSCRATCH,
    OPTION_OFLAGS,
    OPTION_OSTACK,
    OPTION_OFRAME,
    OPTION_OGLOBALS,
    OPTION_OSYSV,
    OPTION_FORCE,
    OPTION_HELP,
    OPTION_VERSION,
};

static bool strToBool(const char *str)
{
    if (str == nullptr)
        return true;
    if (strcmp(str, "true") == 0 || strcmp(str, "1") == 0)
        return true;
    else if (strcmp(str, "false") == 0 || strcmp(str, "0") == 0)
        return false;
    error("expected Boolean argument (true/false); found \"%s\"",
        str);
}

static unsigned strToInt(const char *str)
{
    unsigned x = 0;
    const char *s;
    for (s = str; *s >= '0' && *s <= '9'; s++)
    {
        x *= 10;
        x += (*s - '0');
    }
    if (*s != '\0')
        error("expected integer argument; found \"%s\"", str);
    return x;
}

static void usage(const char *progname)
{
    printf("usage: %s [OPTIONS] binary\n", progname);
    fputs(
        "\n"
        "OPTIONS:\n"
        "\t-Xlowfat (-Xlowfat=false)\n"
        "\t\tEnable (disable) low fat pointer checking [enabled]\n"
        "\t-Xreads (-Xreads=false)\n"
        "\t\tEnable (disable) read checking [disabled]\n"
        "\t-Xwrites (-Xwrites=false)\n"
        "\t\tEnable (disable) write checking [enabled]\n"
        "\t-Xstack (-Xstack=false)\n"
        "\t\tEnable (disable) stack pointer (%rsp) checking [enabled]\n"
        "\t-Xframe (-Xframe=false)\n"
        "\t\tEnable (disable) frame pointer (%rbp) checking [enabled]\n"
        "\t-Xglobal (-Xglobal=false)\n"
        "\t\tEnable (disable) global pointer (%rip/no-base) checking\n"
        "\t\t[enabled]\n"
        "\t-Xsize (-Xsize=false)\n"
        "\t\tEnable (disable) paranoid size checking [enabled]\n"
        "\t-Xadjust (-Xadjust=false)\n"
        "\t\tEnable (disable) experimental base adjustment mode [disabled]\n"
        "\t-Xdebug (-Xdebug=false)\n"
        "\t\tEnable (disable) debug-mode checking [disabled]\n"
        "\t-Xallowlist-use[=filename]\n"
        "\t\tEnable the use of the given allowlist for -Xlowfat\n"
        "\t-Xallowlist-gen[=filename]\n"
        "\t\tEnable allowlist generation instrumentation\n"
        "\t-Xallowlist-mode=MODE\n"
        "\t\tSet the allowlist MODE by allow-list index 0..3\n"
        "\t\t(0=lowfat-unsafe, 1=lowfat-safe, 2=nonfat-only, 3=not-reached)\n"
        "\t\t(-=no-instrumentation, R=redzone-only, L=redzone+lowfat)\n"
        "\t\t[MODE=RLRR]\n"
        "\t-Obatch=N\n"
        "\t\tCheck batch optimization size [N=50]\n"
        "\t-Omerge (-Omerge=false)\n"
        "\t\tEnable (disable) check merging optimization [enabled]\n"
        "\t-Oscratch (-Oscratch=false)\n"
        "\t\tEnable (disable) scratch register optimization [enabled]\n"
        "\t-Oflags (-Oflags=false)\n"
        "\t\tEnable (disable) flags register optimization [enabled]\n"
        "\t-Ostack (-Ostack=false)\n"
        "\t\tEnable (disable) stack check elimination optimization [enabled]\n"
        "\t-Oframe (-Oframe=false)\n"
        "\t\tEnable (disable) frame check elimination optimization\n"
        "\t\t[disabled]\n"
        "\t-Oglobal (-Oglobal=false)\n"
        "\t\tEnable (disable) globals check elimination optimization\n"
        "\t\t[enabled]\n"
        "\t-Osysv (-Osysv=false)\n"
        "\t\tEnable (disable) SYSV ABI optimization [disabled]\n"
        "\t-force (-force=false)\n"
        "\t\tEnable (disable) instrumentation even for incompatible\n"
        "\t\tbinaries [disabled]\n"
        "\t-o OUTPUT\n"
        "\t\tSet OUTPUT to be the output binary filename [a.out]\n"
        "\t-P (-P=false)\n"
        "\t\tEnable (disable) profiling [disabled]\n"
        "\t-v\n"
        "\t\tEnable verbose output [disabled]\n"
        "\t-help\n"
        "\t\tPrint this message\n"
        "\t--version\n"
        "\t\tPrint version information\n\n", stdout);
}

int main(int argc, char **argv)
{
    option_is_tty = isatty(STDERR_FILENO);

    static const struct option long_options[] =
    {
        {"Xlowfat",        optional_argument, nullptr, OPTION_XLOWFAT},
        {"Xreads",         optional_argument, nullptr, OPTION_XREADS},
        {"Xwrites",        optional_argument, nullptr, OPTION_XWRITES},
        {"Xstack",         optional_argument, nullptr, OPTION_XSTACK},
        {"Xframe",         optional_argument, nullptr, OPTION_XFRAME},
        {"Xglobal",        optional_argument, nullptr, OPTION_XGLOBALS},
        {"Xsize",          optional_argument, nullptr, OPTION_XSIZE},
        {"Xadjust",        optional_argument, nullptr, OPTION_XADJUST},
        {"Xdebug",         optional_argument, nullptr, OPTION_XDEBUG},
        {"Xallowlist-use", optional_argument, nullptr, OPTION_XALLOWLIST_USE},
        {"Xallowlist-gen", optional_argument, nullptr, OPTION_XALLOWLIST_GEN},
        {"Xallowlist-mode",required_argument, nullptr, OPTION_XALLOWLIST_MODE},
        {"Oelim",          optional_argument, nullptr, OPTION_OELIM},
        {"Obatch",         required_argument, nullptr, OPTION_OBATCH},
        {"Omerge",         optional_argument, nullptr, OPTION_OMERGE},
        {"Oscratch",       optional_argument, nullptr, OPTION_OSCRATCH},
        {"Oflags",         optional_argument, nullptr, OPTION_OFLAGS},
        {"Ostack",         optional_argument, nullptr, OPTION_OSTACK},
        {"Oframe",         optional_argument, nullptr, OPTION_OFRAME},
        {"Oglobal",        optional_argument, nullptr, OPTION_OGLOBALS},
        {"Osysv",          optional_argument, nullptr, OPTION_OSYSV},
        {"force",          optional_argument, nullptr, OPTION_FORCE},
        {"help",           no_argument,       nullptr, OPTION_HELP},
        {"version",        no_argument,       nullptr, OPTION_VERSION},
        {nullptr,          no_argument,       nullptr, 0},
    };

    bool option_xlowfat                = true;
    bool option_xreads                 = false;
    bool option_xwrites                = true;
    bool option_xstack                 = true;
    bool option_xframe                 = true;
    bool option_xglobals               = true;
    bool option_xsize                  = true;
    bool option_xadjust                = false;
    bool option_xdebug                 = false;
    bool option_xallowlist_use         = false;
    bool option_xallowlist_gen         = false;
    const char *option_xallowlist      = nullptr;
    const char *option_xallowlist_mode = "RLRR";
    bool option_oelim                  = true;
    unsigned option_obatch             = 50;
    bool option_omerge                 = true;
    bool option_oscratch               = true;
    bool option_oflags                 = true;
    bool option_ostack                 = true;
    bool option_oframe                 = false;
    bool option_oglobals               = true;
    bool option_osysv                  = false;
    bool option_force                  = false;
    bool option_profile                = false;
    bool option_verbose                = false;
    const char *option_output          = nullptr;

    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "Po:v", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_XLOWFAT:
                option_xlowfat = strToBool(optarg);
                break;
            case OPTION_XREADS:
                option_xreads = strToBool(optarg);
                break;
            case OPTION_XWRITES:
                option_xwrites = strToBool(optarg);
                break;
            case OPTION_XSTACK:
                option_xstack = strToBool(optarg);
                break;
            case OPTION_XFRAME:
                option_xframe = strToBool(optarg);
                break;
            case OPTION_XGLOBALS:
                option_xglobals = strToBool(optarg);
                break;
            case OPTION_XSIZE:
                option_xsize = strToBool(optarg);
                break;
            case OPTION_XADJUST:
                option_xadjust = strToBool(optarg);
                break;
            case OPTION_XDEBUG:
                option_xdebug = strToBool(optarg);
                break;
            case OPTION_XALLOWLIST_GEN:
                option_xallowlist_gen = true;
                option_xallowlist = optarg;
                break;
            case OPTION_XALLOWLIST_USE:
                option_xallowlist_use = true;
                option_xallowlist = optarg;
                break;
            case OPTION_XALLOWLIST_MODE:
                option_xallowlist_mode = optarg;
                break;
            case OPTION_OELIM:
                option_oelim = strToBool(optarg);
                break;
            case OPTION_OBATCH:
                option_obatch = strToInt(optarg);
                if (option_obatch < 1 || option_obatch > 99)
                    error("failed to parse `-Obatch' option; value must "
                        "be within the range 1..99, found %u", option_obatch);
                break;
            case OPTION_OMERGE:
                option_omerge = strToBool(optarg);
                break;
            case OPTION_OSCRATCH:
                option_oscratch = strToBool(optarg);
                break;
            case OPTION_OFLAGS:
                option_oflags = strToBool(optarg);
                break;
            case OPTION_OSTACK:
                option_ostack = strToBool(optarg);
                break;
            case OPTION_OFRAME:
                option_oframe = strToBool(optarg);
                break;
            case OPTION_OGLOBALS:
                option_oglobals = strToBool(optarg);
                break;
            case OPTION_OSYSV:
                option_osysv = strToBool(optarg);
                break;
            case OPTION_FORCE:
                option_force = strToBool(optarg);
                break;
            case OPTION_HELP:
                usage(argv[0]);
                exit(EXIT_SUCCESS);
            case OPTION_VERSION:
                printf("RedFat " STRING(VERSION) "\n");
                exit(EXIT_SUCCESS);
            case 'P':
                option_profile = true;
                break;
            case 'o':
                option_output = strdup(optarg);
                break;
            case 'v':
                option_verbose = true;
                break;
            default:
                error("failed to parse command-line options; try `--help' "
                    "for more information");
        }
    }

    printf(
        "     %s____          _ _____     _%s\n"
        "    %s|  _ \\ ___  __| |  ___|_ _| |_%s\n" 
        "--- %s| |_) / _ \\/ _` | |_ / _` | __|%s -----------------------\n"
        "    %s|  _ <  __/ (_| |  _| (_| | |_%s\n"
        "    %s|_| \\_\\___|\\__,_|_|  \\__,_|\\__|%s "
            "BINARY HARDENING SYSTEM\n\n",
        (option_is_tty? "\33[31m": ""), (option_is_tty? "\33[0m": ""),
        (option_is_tty? "\33[31m": ""), (option_is_tty? "\33[0m": ""),
        (option_is_tty? "\33[31m": ""), (option_is_tty? "\33[0m": ""),
        (option_is_tty? "\33[31m": ""), (option_is_tty? "\33[0m": ""),
        (option_is_tty? "\33[31m": ""), (option_is_tty? "\33[0m": ""));

    if (optind >= argc)
        error("missing input file; try `--help' for more information");
    if (option_xallowlist_gen && option_xallowlist_use)
        error("option `-Xallowlist-gen' cannot be used with "
            "`-Xallowlist-use'");
    std::string input(argv[optind]);
    std::string output, base;
    if (option_output != nullptr)
    {
        output += option_output;
        base   += option_output;
    }
    else
    {
        char *tmp = strdup(input.c_str());
        if (tmp == nullptr)
            error("failed to duplicate \"%s\" string: %s", input.c_str(),
                strerror(ENOMEM));
        base   += basename(tmp);
        output += base;
        output += (option_xallowlist_gen? ".gen": ".redfat");
        free(tmp);
    }

    if ((option_xallowlist_gen || option_xallowlist_use) &&
            option_xallowlist == nullptr)
    {
        std::string allowlist;
        allowlist += base;
        allowlist += ".allow";
        option_xallowlist = strdup(allowlist.c_str());
    }
    if (option_xallowlist_use)
    {
        FILE *stream = fopen(option_xallowlist, "r");
        if (stream == NULL && errno == ENOENT)
            error("failed to open allow-list \"%s\": %s\n"
                "         %sHint: use `-Xallowlist-gen' to generate an "
                "allow-list%s",
                option_xallowlist, strerror(errno),
                (option_is_tty? "\33[33m": ""),
                (option_is_tty? "\33[0m": ""));
        fclose(stream);
        if (option_xadjust)
            warning("option `-Xallowlist-use=...' may not work correctly "
                "with `-Xadjust=true'");
    }

    if (option_xallowlist_gen)
    {
        // No optimization for allowlist generation
        option_obatch  = 1;
        option_omerge  = false;
        option_xreads  = true;
        option_xwrites = true;
        option_ostack  = true;
        option_xadjust = false;
    }
    else if (option_xdebug)
    {
        option_obatch = 1;
        option_omerge = false;
        if (!option_xlowfat || !option_xsize || !option_xreads ||
                !option_xwrites)
            warning("options `-Xlowfat=true', `-Xsize=true', `-Xreads=true', "
                "and `-Xwrites=true' are implied by option `-Xdebug'");
        if (option_xallowlist_use)
            warning("option `-Xallowlist-use=...' is ignored by option "
                "`-Xdebug'");
        if (option_xadjust)
            warning("option `-Xadjust=true' is ignored by option "
                "`-Xdebug'");
        option_xlowfat        = true;
        option_xsize          = true;
        option_xreads         = true;
        option_xwrites        = true;
        option_xallowlist_use = false;
        option_xadjust        = false;
    }

    std::string path;
    getExePath(path);
    std::string plugin;
    plugin += path;
    plugin += "/RedFatPlugin.so";
    std::string plugin_opt;
    plugin_opt += "--plugin=\"";
    plugin_opt += plugin;
    plugin_opt += "\":";

    std::string command;
    
    command += '\"';
    command += path;
    command += '/';
    command += "e9tool";
    command += '\"';
    command += ' ';
    command += "-o \"";
    command += output;
    command += '\"';
    command += ' ';
    command += "-M 'plugin(\"";
    command += plugin;
    command += "\").match()'";
    command +=  ' ';
    if (option_xallowlist_gen)
    {
        command += "-P 'redfat_allowlist_check("
            "(static)addr,"
            "mem[0].base,"
            "&mem[0],"
            "mem[0].size,"
            "asm)@\"";
        command += path;
        command += "/redfat-rt\"'";
        command += ' ';
    }
    else if (option_xdebug)
    {
        command += "-P 'redfat_debug_check("
            "(static)addr,"
            "mem[0].base,"
            "&mem[0],"
            "mem[0].size,"
            "asm)@\"";
        command += path;
        command += "/redfat-rt\"'";
        command += ' ';
    }
    else
    {
        command += "-P 'plugin(\"";
        command += plugin;
        command += "\").patch()'";
        command += ' ';
    }

    command += plugin_opt;
    command += "-path=\"";
    command += path;
    command += "\" ";
    if (option_verbose)
    {
        command += plugin_opt;
        command += "-log=true ";
    }
    if (option_force)
    {
        command += plugin_opt;
        command += "-force=true ";
    }
    if (option_xdebug)
    {
        command += plugin_opt;
        command += "-Xdebug=true ";
    }
    if (option_xadjust)
    {
        command += plugin_opt;
        command += "-Xadjust=true ";
    }
    command += plugin_opt;
    command += "-Xlowfat=";
    command += (option_xlowfat? "true ": "false ");
    command += plugin_opt;
    command += "-Xreads=";
    command += (option_xreads? "true ": "false ");
    command += plugin_opt;
    command += "-Xwrites=";
    command += (option_xwrites? "true ": "false ");
    command += plugin_opt;
    command += "-Xstack=";
    command += (option_xstack? "true ": "false ");
    command += plugin_opt;
    command += "-Xframe=";
    command += (option_xframe? "true ": "false ");
    command += plugin_opt;
    command += "-Xsize=";
    command += (option_xsize? "true ": "false ");
    command += plugin_opt;
    command += "-Xprofile=";
    command += (option_profile? "true ": "false ");
    command += plugin_opt;
    command += "-Oelim=";
    command += (option_oelim? "true ": "false ");
    command += plugin_opt;
    command += "-Obatch=";
    command += std::to_string(option_obatch);
    command += ' ';
    command += plugin_opt;
    command += "-Omerge=";
    command += (option_omerge? "true ": "false ");
    command += plugin_opt;
    command += "-Oscratch=";
    command += (option_oscratch? "true ": "false ");
    command += plugin_opt;
    command += "-Oflags=";
    command += (option_oflags? "true ": "false ");
    command += plugin_opt;
    command += "-Ostack=";
    command += (option_ostack? "true ": "false ");
    command += plugin_opt;
    command += "-Oframe=";
    command += (option_oframe? "true ": "false ");
    command += plugin_opt;
    command += "-Osysv=";
    command += (option_osysv? "true ": "false ");
    if (option_xallowlist_gen)
    {
        command += plugin_opt;
        command += "-Xallowlist-gen=\"";
        command += option_xallowlist;
        command += '\"';
    }
    else if (option_xallowlist_use)
    {
        command += plugin_opt;
        command += "-Xallowlist-use=\"";
        command += option_xallowlist;
        command += "\" ";
        command += plugin_opt;
        command += "-Xallowlist-mode=";
        command += option_xallowlist_mode;
    }
    command += ' ';

    for (int i = optind; i < argc; i++)
    {
        command += '\'';
        command += argv[i];
        command += '\'';
        command += ' ';
    }

    fprintf(stderr, "Executing %s%s%s\n", (option_is_tty? "\33[32m": ""),
        command.c_str(), (option_is_tty? "\33[0m": ""));
    if (!option_verbose)
        command += "--option --log=false";
    
    int result = system(command.c_str());
    if (result != 0)
        error("e9tool command failed with status (%d)", result);

    printf("Generated \"%s%s%s\"\n\n",
        (option_is_tty? "\33[32m": ""), output.c_str(),
        (option_is_tty? "\33[0m": ""));

    if (option_xlowfat && !option_xdebug &&
            !(option_xallowlist_use || option_xallowlist_gen))
        warning("using `-Xlowfat=true' without "
            "`-Xallowlist-gen'/`-Xallowlist-use' may result in false error "
            "reports for some binaries");

    printf("%sUSAGE%s:\n\n",
        (option_is_tty? "\33[33m": ""), (option_is_tty? "\33[0m": ""));
    if (option_xallowlist_gen)
    {
        printf("\tThe output binary can be used for allow-list "
            "generation.\n");
        printf("\tTo use, run the binary on one or more test cases, "
            "e.g.:\n\n");
        printf("\t    %s$ LD_PRELOAD=%s/libredfat.so ./%s ...%s\n\n",
            (option_is_tty? "\33[36m": ""), path.c_str(), output.c_str(),
            (option_is_tty? "\33[0m": ""));
        printf("\tNote that:\n");
        printf("\t    - The \"libredfat.so\" library must be LD_PRELOAD'ed.\n");
        printf("\t    - The allow-list will be stored the \"%s\" file.\n\n",
            option_xallowlist);
    }
    else
    {
        printf("\tThe output binary has been hardened with "
                "%sREDZONE%s%s%s%s%s protection.\n",
            (option_is_tty? "\33[33m": ""),
            (option_is_tty? "\33[0m": ""),
            (option_xlowfat? " and ": ""),
            (option_xlowfat && option_is_tty? "\33[33m": ""),
            (option_xlowfat? "LOWFAT": ""),
            (option_xlowfat && option_is_tty? "\33[0m": ""));
        printf("\tTo use, run the binary as follows:\n\n");
        printf("\t    %s$ LD_PRELOAD=%s/libredfat.so ./%s ...%s\n\n",
            (option_is_tty? "\33[36m": ""), path.c_str(), output.c_str(),
            (option_is_tty? "\33[0m": ""));
        printf("\tNote that the \"libredfat.so\" library must be "
            "LD_PRELOAD'ed, else the\n");
        printf("\toutput binary will refuse to run.\n\n");
    }

    return 0;
}

