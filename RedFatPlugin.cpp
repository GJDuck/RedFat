/*      ____          _ _____     _   
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

#include <map>
#include <string>
#include <set>

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include <getopt.h>
#include <sys/mman.h>

#include "e9plugin.h"
using namespace e9tool;

#include "redfat-rt.h"

/*************************************************************************/
/* MISC.                                                                 */
/*************************************************************************/

/*
 * Prototypes.
 */
static const OpInfo *getMemOp(const InstrInfo *I);

/*
 * Instrumentation.
 */
enum Instrumentation : uint8_t
{
    MODE_NONE,              // Do-not-instrument
    MODE_REDZONE,           // Redzone-only
    MODE_LOWFAT             // Redzone+lowfat
};

/*
 * Options.
 */
static bool   REDFAT_XREADS         = false;
static bool   REDFAT_XWRITES        = true;
static bool   REDFAT_XLOWFAT        = false;
static bool   REDFAT_XSTACK         = true;
static bool   REDFAT_XFRAME         = true;
static bool   REDFAT_XGLOBALS       = true;
static bool   REDFAT_XSIZE          = false;
static bool   REDFAT_XADJUST        = false;
static bool   REDFAT_XALLOWLIST_GEN = false;
static bool   REDFAT_XALLOWLIST_USE = false;
static bool   REDFAT_XPROFILE       = false;
static bool   REDFAT_OELIM          = true;
static size_t REDFAT_OBATCH         = 50;
static bool   REDFAT_OMERGE         = true;
static bool   REDFAT_OSCRATCH       = true;
static bool   REDFAT_OFLAGS         = true;
static bool   REDFAT_OSTACK         = true;
static bool   REDFAT_OFRAME         = false;
static bool   REDFAT_OGLOBALS       = true;
static bool   REDFAT_OSYSV          = false;
static bool   REDFAT_LOG            = false;
static bool   REDFAT_FORCE          = false;

static const char *REDFAT_XALLOWLIST = nullptr;
static Instrumentation REDFAT_XALLOWLIST_MODE[] =
{
    MODE_REDZONE,       // Lowfat-Unsafe
    MODE_LOWFAT,        // Lowfat-Safe
    MODE_REDZONE,       // Nonfat-only
    MODE_REDZONE        // Not-reached
};

/*
 * Logging.
 */
static void log(char c)
{
    if (!REDFAT_LOG)
        return;
    fputc(c, stderr);
}
static void log(const char *msg, ...)
{
    if (!REDFAT_LOG)
        return;
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
}

/*
 * Allow-list
 */
static std::map<uintptr_t, int8_t> allowlist;
static Instrumentation allowlist_lookup(const InstrInfo *I)
{
    if (!REDFAT_XALLOWLIST_USE)
    {
        // Allow-list disabled = always instrument with Lowfat
        return REDFAT_XALLOWLIST_MODE[ALLOW_LOWFAT];
    }
    auto i = allowlist.find(I->address);
    if (allowlist.find(I->address) == allowlist.end())
    {
        // Not covered = do not instrument with Lowfat
        return REDFAT_XALLOWLIST_MODE[ALLOW_UNKNOWN];
    }
    const OpInfo *op = getMemOp(I);
    if (op == nullptr || op->mem.base == REGISTER_NONE)
        return REDFAT_XALLOWLIST_MODE[ALLOW_UNKNOWN];
    return REDFAT_XALLOWLIST_MODE[i->second];
}

/*************************************************************************/
/* REGISTERS                                                             */
/*************************************************************************/

/*
 * Translate an x86_reg into an x64 register number.
 */
static int regno(Register reg)
{
    switch (reg)
    {
        case REGISTER_AH: case REGISTER_AL:
        case REGISTER_AX: case REGISTER_EAX: case REGISTER_RAX:
            return 0;
        case REGISTER_CH: case REGISTER_CL:
        case REGISTER_CX: case REGISTER_ECX: case REGISTER_RCX:
            return 1;
        case REGISTER_DH: case REGISTER_DL:
        case REGISTER_DX: case REGISTER_EDX: case REGISTER_RDX:
            return 2;
        case REGISTER_BH: case REGISTER_BL:
        case REGISTER_BX: case REGISTER_EBX: case REGISTER_RBX:
            return 3;
        case REGISTER_SP: case REGISTER_SPL: case REGISTER_ESP:
        case REGISTER_RSP:
            return 4;
        case REGISTER_BP: case REGISTER_BPL: case REGISTER_EBP:
        case REGISTER_RBP:
            return 5;
        case REGISTER_SI: case REGISTER_SIL: case REGISTER_ESI:
        case REGISTER_RSI:
            return 6;
        case REGISTER_DI: case REGISTER_DIL: case REGISTER_EDI:
        case REGISTER_RDI:
            return 7;
        case REGISTER_R8B: case REGISTER_R8W: case REGISTER_R8D:
        case REGISTER_R8:
            return 8;
        case REGISTER_R9B: case REGISTER_R9W: case REGISTER_R9D:
        case REGISTER_R9:
            return 9;
        case REGISTER_R10B: case REGISTER_R10W: case REGISTER_R10D:
        case REGISTER_R10:
            return 10;
        case REGISTER_R11B: case REGISTER_R11W: case REGISTER_R11D:
        case REGISTER_R11:
            return 11;
        case REGISTER_R12B: case REGISTER_R12W: case REGISTER_R12D:
        case REGISTER_R12:
            return 12;
        case REGISTER_R13B: case REGISTER_R13W: case REGISTER_R13D:
        case REGISTER_R13:
            return 13;
        case REGISTER_R14B: case REGISTER_R14W: case REGISTER_R14D:
        case REGISTER_R14:
            return 14;
        case REGISTER_R15B: case REGISTER_R15W: case REGISTER_R15D:
        case REGISTER_R15:
            return 15;
        default:
            return -1;
    }
}

/*
 * Returns `true' if the whole 64bit register will be clobbered with a write.
 * (Either directly or by zero-extension).
 */
static bool regClobbered(Register reg)
{
    switch (reg)
    {
        case REGISTER_EAX: case REGISTER_RAX:
            return true;
        case REGISTER_ECX: case REGISTER_RCX:
            return true;
        case REGISTER_EDX: case REGISTER_RDX:
            return true;
        case REGISTER_EBX: case REGISTER_RBX:
            return true;
        case REGISTER_ESP: case REGISTER_RSP:
            return true;
        case REGISTER_EBP: case REGISTER_RBP:
            return true;
        case REGISTER_ESI: case REGISTER_RSI:
            return true;
        case REGISTER_EDI: case REGISTER_RDI:
            return true;
        case REGISTER_R8D: case REGISTER_R8:
            return true;
        case REGISTER_R9D: case REGISTER_R9:
            return true;
        case REGISTER_R10D: case REGISTER_R10:
            return true;
        case REGISTER_R11D: case REGISTER_R11:
            return true;
        case REGISTER_R12D: case REGISTER_R12:
            return true;
        case REGISTER_R13D: case REGISTER_R13:
            return true;
        case REGISTER_R14D: case REGISTER_R14:
            return true;
        case REGISTER_R15D: case REGISTER_R15:
            return true;
        default:
            return false;
    }
}

/*
 * Get register name from register index.
 */
static const char *regNameFromIdx(int r)
{
    switch (r)
    {
        case 0:  return "%rax";
        case 1:  return "%rcx";
        case 2:  return "%rdx";
        case 3:  return "%rbx";
        case 4:  return "%rsp";
        case 5:  return "%rbp";
        case 6:  return "%rsi";
        case 7:  return "%rdi";
        case 8:  return "%r8";
        case 9:  return "%r9";
        case 10: return "%r10";
        case 11: return "%r11";
        case 12: return "%r12";
        case 13: return "%r13";
        case 14: return "%r14";
        case 15: return "%r15";
        default: return "???";
    }
}
static const char *regName(Register reg)
{
    return regNameFromIdx(regno(reg));
}

/*
 * Representation of a register set.
 * (Implemented as a bitset over the regno).
 */
struct RegSet
{
    uint32_t regs = 0;

    void clear()
    {
        regs = 0;
    }

    bool get(Register reg) const
    {
        int r = regno(reg);
        if (r < 0)
            return false;
        return (((1 << r) & regs) != 0);
    }

    bool member(Register reg) const
    {
        return get(reg);
    }

    void set(Register reg, bool val)
    {
        int r = regno(reg);
        if (r < 0)
            return;
        if (val)
            regs |= (1 << r);
        else
            regs &= ~(1 << r);
    }

    void add(Register reg)
    {
        set(reg, true);
    }

    void remove(Register reg)
    {
        set(reg, false);
    }

    void dump() const
    {
        log('{');
        bool prev = false;
        for (unsigned r = 0; r < 16; r++)
        {
            if (((1 << r) & regs) == 0)
                continue;
            if (prev)
                log(',');
            prev = true;
            log("%s", regNameFromIdx(r));
        }
        log('}');
    }
};

/*************************************************************************/
/* CODEGEN SUPPORT                                                       */
/*************************************************************************/

/*
 * Representation of a memory operation that is scheduled to be checked.
 * (part of a batch of instructions to be checked).
 */
struct BatchEntry
{
    const Instr *I;                     // Instruction to be checked 
    ssize_t lb;                         // Lower bound
    ssize_t ub;                         // Upper bound
    bool read = false;                  // Read only?
    bool redzone = true;                // Redzone check?
    bool lowfat = false;                // LowFat check?
    bool removed = false;               // Removed?

    BatchEntry(const Instr *I, ssize_t lb, ssize_t ub) : I(I), lb(lb), ub(ub)
    {
        ;
    }
};

/*
 * Adjustments.
 */
typedef std::map<Register, off_t> Adjusts;

/*
 * Representation of a batch of instructions to be checked.
 */
struct Batch
{
    std::vector<BatchEntry> entries;    // Instructions & bounds
    Adjusts adjusts;                    // Adjustments
    RegSet scratch;                     // Available scratch registers
    bool clobber_flags = false;         // Can clobber %rflags?
};

/*
 * RedFat info/state.
 */
struct RedFat
{
    const ELF *elf = nullptr;                           // The ELF file
    const Instr *Is = nullptr;                          // All instrs
    size_t size = 0;                                    // size of Is
    Targets targets;                                    // Jump targets
    std::map<intptr_t, Batch> batches;                  // All batches
    RegSet clobbered;                                   // Current clobbers
    std::vector<BatchEntry> batch;                      // Current batch

    // Stats
    unsigned num_reads  = 0;
    unsigned num_writes = 0;
    size_t batches_num  = 0;
    size_t batches_size = 0;
};

/*
 * Stats.
 */
struct Stats
{
    unsigned num_redzone_reads_unopt;
    unsigned num_redzone_writes_unopt;
    unsigned num_redzone_reads_opt;
    unsigned num_redzone_writes_opt;
    unsigned num_lowfat_reads_unopt;
    unsigned num_lowfat_writes_unopt;
    unsigned num_lowfat_reads_opt;
    unsigned num_lowfat_writes_opt;
};

/*
 * Collect stats.
 */
static void getStats(const std::vector<BatchEntry> &entries, Stats *stats)
{
    memset(stats, 0, sizeof(*stats));
    for (const auto &entry: entries)
    {
        if (entry.read && entry.redzone)
            stats->num_redzone_reads_unopt++;
        if (!entry.read && entry.redzone)
            stats->num_redzone_writes_unopt++;
        if (entry.read && entry.lowfat)
            stats->num_lowfat_reads_unopt++;
        if (!entry.read && entry.lowfat)
            stats->num_lowfat_writes_unopt++;
        if (!entry.removed)
        {
            if (entry.read && entry.redzone)
                stats->num_redzone_reads_opt++;
            if (!entry.read && entry.redzone)
                stats->num_redzone_writes_opt++;
            if (entry.read && entry.lowfat)
                stats->num_lowfat_reads_opt++;
            if (!entry.read && entry.lowfat)
                stats->num_lowfat_writes_opt++;
        }
    }
}

/*
 * Save a register value to TLS.
 */
static void emitSAVE(FILE *stream, int32_t offset, Register regA)
{
    int a = regno(regA);
    uint8_t rex = 0x48 | (a >= 8? 0x04: 0x00);
    uint8_t modrm = (0x00 << 6) | ((uint8_t)(a & 0x7) << 3) | 0x04;
    fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},",
        0x64, rex, 0x89, modrm, 0x25, offset);
}

/*
 * Restore a register value from TLS.
 */
static void emitRESTORE(FILE *stream, int32_t offset, Register regA)
{
    int a = regno(regA);
    uint8_t rex = 0x48 | (a >= 8? 0x04: 0x00);
    uint8_t modrm = (0x00 << 6) | ((uint8_t)(a & 0x7) << 3) | 0x04;
    fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},",
        0x64, rex, 0x8b, modrm, 0x25, offset);
}

/*
 * Load a 64bit value from an address (table+regA) into regB.
 */
static void emitLOAD(FILE *stream, int32_t table, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);
    uint8_t rex = 0x48 | (a >= 8? 0x02: 0x00) | (b >= 8? 0x04: 0x00);
    uint8_t modrm = (0x00 << 6) | ((uint8_t)(b & 0x7) << 3) | 0x04;
    uint8_t sib = 0xc5 | ((uint8_t)(a & 0x7) << 3);
    fprintf(stream, "%u,%u,%u,%u,{\"int32\":%d},",
        rex, 0x8b, modrm, sib, table);
}

/*
 * Converts a memory-access instruction (I) into a "Load Effective Address"
 * (LEA) instruction that loads the corresponding pointer into the reg.
 */
static void emitLEA(FILE *stream, const InstrInfo *I, int32_t ub, Register reg)
{
    int r = regno(reg);

    uint8_t rex = (r < 8? 0x48: 0x4c);
    if (I->hasREX())
        rex |= (I->getREX() & 0x03);
    else if (I->hasVEX())
    {
        uint32_t vex = I->getVEX();
        rex |= ((vex & 0xFF) == 0xC4? (~vex & 0x6000) >> 13: 0x00);
    }
    else if (I->hasEVEX())
    {
        uint32_t evex = I->getEVEX();
        rex |= (evex & 0x6000) >> 13;
    }

    uint8_t modrm = I->getMODRM();
    modrm = (modrm & 0xc7) | (((uint8_t)r & 0x7) << 3);

    uint8_t mod   = (modrm >> 6) & 0x3;
    uint8_t rm    = modrm & 0x7;
    uint8_t base  = 0;
    uint8_t sib   = I->getSIB();
    if (I->hasSIB())
        base = sib & 0x7;

    assert(!((mod == 0x0 && rm == 0x5)));   // No PC-rel!

    intptr_t disp = (intptr_t)ub;
    switch (mod)
    {
        case 0x00:
            if (base == 0x5)
                break;
            if (disp >= INT8_MIN && disp <= INT8_MAX)
                modrm = (modrm & 0x3f) | (0x01 << 6);
            else
                modrm = (modrm & 0x3f) | (0x02 << 6);
            break;
        case 0x01:
            if (disp < INT8_MIN || disp > INT8_MAX)
                modrm = (modrm & 0x3f) | (0x02 << 6);
            break;
        default:
            break;
    }

    fprintf(stream, "%u,%u,%u,", rex, 0x8d, modrm);
    if (I->hasSIB())
        fprintf(stream, "%u,", sib);
    mod = (modrm >> 6) & 0x3;
    switch (mod)
    {
        case 0x00:
            if (I->hasSIB() && base == 0x5)
                fprintf(stream, "{\"int32\":%d},", (int32_t)disp);
            break;
        case 0x01:
            fprintf(stream, "{\"int8\":%d},", (int32_t)disp);
            break;
        case 0x02:
            fprintf(stream, "{\"int32\":%d},", (int32_t)disp);
            break;
    }
}

/*
 * Move a 32bit constant (x) into reg.
 */
static void emitMOV(FILE *stream, uint32_t x, Register reg)
{
    int r = regno(reg);
    if (r >= 8)
        fprintf(stream, "%u,", 0x41);
    uint8_t opcode = 0xb8 + (r & 0x7);
    fprintf(stream, "%u,{\"int32\":%d},", opcode, (int)x);
}

/*
 * Move between two 64bit registers.
 */
static void emitMOV(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);
    if (a == b)
        return;
    uint8_t rex = 0x48;
    rex |= (a >= 8? 0x04: 0x00);
    rex |= (b >= 8? 0x01: 0x00);
    uint8_t modrm = 0xc0 | (uint8_t)(b & 0x7) | ((uint8_t)(a & 0x7) << 3);
    fprintf(stream, "%u,%u,%u,", rex, 0x89, modrm);
}

/*
 * Move 64bit registers with adjustment.
 */
static void emitADJUST(FILE *stream, off_t adjust, Register regA,
    Register regB)
{
    if (adjust == 0 || adjust < INT32_MIN || adjust > INT32_MAX)
    {
        emitMOV(stream, regA, regB);
        return;
    }
    int a = regno(regA);
    int b = regno(regB);
    uint8_t rex = 0x48;
    rex |= (b >= 8? 0x04: 0x00);
    rex |= (a >= 8? 0x01: 0x00);
    
    uint8_t mod = 0x00;
    uint8_t r   = (uint8_t)(b & 0x7);
    uint8_t rm  = (uint8_t)(a & 0x7);
    uint8_t sib = 0x00;
    if (adjust != 0 && adjust >= INT8_MIN && adjust <= INT8_MAX)
        mod = 0x01;
    else
        mod = 0x02;
    if (regA == REGISTER_RSP || regA == REGISTER_R12)
    {
        rm  = 0x04;
        sib = 0x24;
    }
    uint8_t modrm = (mod << 6) | (r << 3) | rm;
    fprintf(stream, "%u,%u,%u,", rex, 0x8d, modrm);
    if (sib != 0x0)
        fprintf(stream, "%u,", sib);
    if (mod == 0x1)
        fprintf(stream, "{\"int8\":%d},", (int32_t)adjust);
    else if (mod == 0x2)
        fprintf(stream, "{\"int32\":%d},", (int32_t)adjust);
}

/*
 * Exchange two 64bit registers.
 */
static void emitXCHG(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);
    if (a == b)
        return;
    if (a > b)
    {
        int tmp = a;
        a = b;
        b = tmp;
    }
    if (a == 0)     // 0 == %rax which needs special handling
    {
        uint8_t rex = (b >= 8? 0x49: 0x48);
        uint8_t opcode = 0x90 + (b & 0x7);
        fprintf(stream, "%u,%u,", rex, opcode);
        return;
    }
    uint8_t rex = 0x48;
    rex |= (a >= 8? 0x01: 0x00);
    rex |= (b >= 8? 0x04: 0x00);
    uint8_t modrm = 0xc0 | (uint8_t)(a & 0x7) | ((uint8_t)(b & 0x7) << 3);
    fprintf(stream, "%u,%u,%u,", rex, 0x87, modrm);
}

/*
 * Dereference the pointer in regA and store the result in regB.
 */
static void emitDEREF(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);
    uint8_t rex = 0x48 | (a >= 8? 0x01: 0x00) | (b >= 8? 0x04: 0x00);
    uint8_t modrm = 0x00 | ((uint8_t)(b & 0x7) << 3) | (uint8_t)(a & 0x7);
    fprintf(stream, "%u,%u,%u,", rex, 0x8b, modrm);
}

/*
 * Emit instructions to calculate the lowfat_index() operation without
 * affecting %rflags.  For this we use BMI2's RORX instruction.
 */
static void emitIDX(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);

    // rorx $35,%regA,%regB
    uint8_t b1 = 0x43 | (a < 8? 0x20: 0x00) | (b < 8? 0x80: 0x00);
    uint8_t b2 = 0xfb;
    uint8_t modrm = 0xc0 | (uint8_t)(a & 0x7) | (((uint8_t)(b & 0x7)) << 3);
    fprintf(stream, "%u,%u,%u,%u,%u,%u,", 0xc4, b1, b2, 0xf0, modrm, 35);

    // movzwl %regBw,%regBd
    modrm = 0xc0 | ((uint8_t)(b & 0x7) << 3) | (uint8_t)(b & 0x7);
    if (b >= 8)
        fprintf(stream, "%u,", 0x45);
    fprintf(stream, "%u,%u,%u,", 0x0f, 0xb7, modrm);
}

/*
 * Swap the upper and lower 32bit word of regA and store the result in regB.
 */
static void emitSWAP(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);

    // rorx $32,%regA,%regB
    uint8_t b1 = 0x43 | (a < 8? 0x20: 0x00) | (b < 8? 0x80: 0x00);
    uint8_t b2 = 0xfb;
    uint8_t modrm = 0xc0 | (uint8_t)(a & 0x7) | (((uint8_t)(b & 0x7)) << 3);
    fprintf(stream, "%u,%u,%u,%u,%u,%u,", 0xc4, b1, b2, 0xf0, modrm, 32);
}

/*
 * Multiplication.
 */
static void emitMUL(FILE *stream, int32_t table, Register regA, Register regB,
    Register regC)
{
    assert(regA != REGISTER_RSP);
    int a = regno(regA);
    int b = regno(regB);
    int c = regno(regC);
    uint8_t b1 = 0x02 | (a < 8? 0x40: 0x00) | (c < 8? 0x80: 0x00);
    uint8_t b2 = 0x83 | (uint8_t)((~b) & 0xf) << 3;
    uint8_t modrm = (0x00 << 6) | (((uint8_t)(c & 0x7)) << 3) | 0x04;
    uint8_t sib   = (0x03 << 6) | (((uint8_t)(a & 0x7)) << 3) | 0x05;
    fprintf(stream, "%u,%u,%u,%u,%u,%u,{\"int32\":%d},", 0xc4, b1, b2, 0xf6,
        modrm, sib, table);
}

/*
 * Multiplication.
 */
static void emitMUL(FILE *stream, Register regA, Register regB, Register regC)
{
    int a = regno(regA);
    int b = regno(regB);
    int c = regno(regC);
    uint8_t b1 = 0x02 | (a < 8? 0x20: 0x00) | (c < 8? 0x80: 0x00);
    uint8_t b2 = 0x83 | (uint8_t)((~b) & 0xf) << 3;
    uint8_t modrm = (0x03 << 6) | (((uint8_t)(c & 0x7)) << 3) |
        ((uint8_t)(a & 0x7));
    fprintf(stream, "%u,%u,%u,%u,%u,", 0xc4, b1, b2, 0xf6, modrm);
}

/*
 * Bitwise negation of reg.
 */
static void emitNOT(FILE *stream, Register reg)
{
    int r = regno(reg);
    uint8_t rex = (r >= 8? 0x49: 0x48);
    uint8_t modrm = 0xd0 | (uint8_t)(r & 0x7);
    fprintf(stream, "%u,%u,%u,", rex, 0xf7, modrm);
}

/*
 * Calculate (regC = offset + regA + regB) without affecting the flags.
 */
static void emitADD(FILE *stream, bool r64, int32_t offset, Register regA,
    Register regB, Register regC)
{
    int a = regno(regA);
    int b = regno(regB);
    int c = regno(regC);

    uint8_t rex = 0x00;
    if (r64 || a >= 8 || b >= 8 || c >= 8)
    {
        rex = 0x40;
        if (r64)
            rex |= 0x08;
        if (c >= 8)
            rex |= 0x04;
        if (a >= 8)
            rex |= 0x01;
        if (b >= 8)
            rex |= 0x02;
    }

    uint8_t mod = 0x00;
    uint8_t rm  = 0x04;
    uint8_t r   = (uint8_t)(c & 0x7);
    if (offset != 0 && offset >= INT8_MIN && offset <= INT8_MAX)
        mod = 0x01;
    else
        mod = 0x02;
    if (mod == 0x00 && (regB == REGISTER_RBP || regB == REGISTER_R13))
        mod = 0x01;
    uint8_t modrm = (mod << 6) | (r << 3) | rm;

    uint8_t scale = 0x00;
    uint8_t idx   = (uint8_t)(b & 0x7);
    uint8_t base  = (uint8_t)(a & 0x7);
    uint8_t sib   = (scale << 6) | (idx << 3) | base;

    if (rex != 0x00)
        fprintf(stream, "%u,", rex);
    fprintf(stream, "%u,%u,%u,", /*LEA=*/0x8d, modrm, sib);
    if (mod == 0x1)
        fprintf(stream, "{\"int8\":%d},", (int32_t)offset);
    else if (mod == 0x2)
        fprintf(stream, "{\"int32\":%d},", (int32_t)offset);
}

/*
 * Subtraction.
 */
static void emitSUB(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);

    uint8_t rex = 0x48 | (b >= 8? 0x04: 0x00) | (a >= 8? 0x01: 0x00);
    uint8_t modrm = 0xc0 | (uint8_t)(b & 0x7) | ((uint8_t)(a & 0x7) << 3);

    fprintf(stream, "%u,%u,%u,", rex, 0x29, modrm);
}

/*
 * Calculate regB = regB + offset.  We are allowed to affect the flags.
 */
static void emitADD(FILE *stream, bool r64, int32_t offset, Register regB)
{
    if (offset == 0)
        return;

    bool sub = false;
    if (offset < 0)
    {
        sub = true;
        offset = -offset;
    }

    bool imm8 = false;
    if (offset >= INT8_MIN && offset <= INT8_MAX)
        imm8 = true;

    int b = regno(regB);
    uint8_t rex = (b >= 8? 0x41: 0x00);
    rex |= (r64? 0x48: 0x00);
    if (b == /*rax=*/0 && !imm8)
    {
        // Special handling for %eax:
        if (rex != 0x00)
            fprintf(stream, "%u,", rex);
        fprintf(stream, "%u,{\"int32\":%d},", (sub? 0x2d: 0x05), offset);
        return;
    }

    uint8_t opcode = (imm8? 0x83: 0x81);
    uint8_t o = (sub? 0x05: 0x00);
    uint8_t modrm = 0xc0 | (o << 3) | ((uint8_t)b & 0x7);

    if (rex != 0x00)
        fprintf(stream, "%u,", rex);
    fprintf(stream, "%u,%u,", opcode, modrm);
    if (imm8)
        fprintf(stream, "{\"int8\":%d},", offset);
    else
        fprintf(stream, "{\"int32\":%d},", offset);
}

/*
 * Emit a comparison with the memory location *regA and a register regB.
 */
static void emitDEREF_CMP(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);
    uint8_t rex = 0x48 | (a >= 8? 0x04: 0x00) | (b >= 8? 0x01: 0x00);
    uint8_t modrm = 0x00 | (uint8_t)(a & 0x7) | ((uint8_t)(b & 0x7) << 3);
    fprintf(stream, "%u,%u,%u,", rex, 0x3b, modrm);
}

/*
 * Emit a comparison between two registers.
 */
static void emitCMP(FILE *stream, Register regA, Register regB)
{
    int a = regno(regA);
    int b = regno(regB);
    uint8_t rex = 0x48 | (b >= 8? 0x04: 0x00) | (a >= 8? 0x01: 0x00);
    uint8_t modrm = 0xc0 | (uint8_t)(a & 0x7) | ((uint8_t)(b & 0x7) << 3);
    fprintf(stream, "%u,%u,%u,", rex, 0x3b, modrm);
}

/*
 * Emit instructions to jump to PASS if (%rcx == 0)
 */
static void emitJMP_IF_PASS(FILE *stream, int check_no)
{ 
    // If (%rcx == 0) then this is a non-fat pointer.
    // jrcxz .Lpassed
    if (!REDFAT_XPROFILE || !REDFAT_XSIZE)
    {
        fprintf(stream, "%u,{\"rel8\":\".Lpassed_%d\"},", 0xe3, check_no);
        return;
    }

    // The target might be too far away for jrcxz...
    fprintf(stream, "%u,{\"rel8\":\".Ltmp_%d\"},", 0xe3, check_no);
    fprintf(stream, "%u,{\"rel8\":\".Lskip_%d\"},", 0xeb, check_no);
    fprintf(stream, "\".Ltmp_%d\",%u,{\"rel32\":\".Lpassed_%d\"},",
        check_no, 0xe9, check_no);
    fprintf(stream, "\".Lskip_%d\",", check_no);
}

/*
 * Emit an instruction to abort the execution.
 */
static void emitABORT(FILE *stream)
{
    fprintf(stream, "%u,%u,", 0x0f, 0x0b);   // ud2
}

/*************************************************************************/
/* CHECK                                                                 */
/*************************************************************************/

/*
 * Emits the trampoline that checks the given batch of instructions.
 */
static void emitCHECK(FILE *stream, const ELF *elf,
    const std::vector<BatchEntry> &entries, const Adjusts &adjusts,
    const RegSet &scratch, bool clobberFlags = false)
{
    if (entries.size() == 0)
        return;
    bool save_scratch = false, save_rcx = !scratch.member(REGISTER_RCX),
         save_rdx = !scratch.member(REGISTER_RDX);
    const Register regs[] =
        {REGISTER_RAX, REGISTER_RBX, REGISTER_RBP, REGISTER_RSI, REGISTER_RDI,
         REGISTER_R8, REGISTER_R9, REGISTER_R10, REGISTER_R11, REGISTER_R12,
         REGISTER_R13, REGISTER_R14, REGISTER_R15};
    Register regScratch[2] = {REGISTER_INVALID, REGISTER_INVALID};
    for (unsigned i = 0; i < sizeof(regs) / sizeof(regs[0]); i++)
    {
        if (scratch.member(regs[i]))
        {
            if (regScratch[0] == REGISTER_INVALID)
                regScratch[0] = regs[i];
            else
            {
                regScratch[1] = regs[i];
                break;
            }
        }
    }

    if (REDFAT_XPROFILE)
    {
        Stats stats;
        getStats(entries, &stats);
        if (!clobberFlags)
        {
            emitSAVE(stream, 0x70, REGISTER_RAX);
            fprintf(stream, "%u,%u,%u,", 0x0f, 0x90, 0xc0);
            fprintf(stream, "%u,", 0x9f);
        }

        // lock add $size,PROFILE
        if (stats.num_redzone_reads_unopt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_REDZONE_READ_UNOPTIMIZED_CHECKS),
                stats.num_redzone_reads_unopt);
        if (stats.num_redzone_writes_unopt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_REDZONE_WRITE_UNOPTIMIZED_CHECKS),
                stats.num_redzone_writes_unopt);
        if (stats.num_lowfat_reads_unopt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_LOWFAT_READ_UNOPTIMIZED_CHECKS),
                stats.num_lowfat_reads_unopt);
        if (stats.num_lowfat_writes_unopt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_LOWFAT_WRITE_UNOPTIMIZED_CHECKS),
                stats.num_lowfat_writes_unopt);
        if (stats.num_redzone_reads_opt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_REDZONE_READ_OPTIMIZED_CHECKS),
                stats.num_redzone_reads_opt);
        if (stats.num_redzone_writes_opt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_REDZONE_WRITE_OPTIMIZED_CHECKS),
                stats.num_redzone_writes_opt);
        if (stats.num_lowfat_reads_opt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_LOWFAT_READ_OPTIMIZED_CHECKS),
                stats.num_lowfat_reads_opt);
        if (stats.num_lowfat_writes_opt != 0)
            fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_LOWFAT_WRITE_OPTIMIZED_CHECKS),
                stats.num_lowfat_writes_opt);

        if (!clobberFlags)
        {
            fprintf(stream, "%u,%u,", 0x04, 0x7f);
            fprintf(stream, "%u,", 0x9e);
            emitRESTORE(stream, 0x70, REGISTER_RAX);
        }
    }

    if (regScratch[0] == REGISTER_INVALID)
    {
        save_scratch = true;
        regScratch[0] = REGISTER_RAX;
        emitSAVE(stream, 0x70, regScratch[0]);
    }
    if (save_rcx)
        emitSAVE(stream, 0x50, REGISTER_RCX);
    if (save_rdx)
        emitSAVE(stream, 0x58, REGISTER_RDX);

    int check_no = 0;
    for (const auto &entry: entries)
    {
        if (entry.removed)
            continue;
        const Instr *i = entry.I;
        ssize_t lb = entry.lb;
        ssize_t ub = entry.ub;
        ssize_t delta = entry.ub - entry.lb;
        assert(lb >= INT32_MIN && ub <= INT32_MAX);
        assert(delta > 0);

        InstrInfo I0, *I = &I0;
        getInstrInfo(elf, i, I);

        Register regIdx = regScratch[0];
        Register regPtr = REGISTER_RDX;
        Register regC   = REGISTER_RCX;

        const OpInfo *op = getMemOp(I);
        assert(op != nullptr);
        Register base = op->mem.base, index = op->mem.index;

        if (check_no > 0)
        {
            if (save_scratch && (base == regScratch[0] ||
                    index == regScratch[0]))
                emitRESTORE(stream, 0x70, regScratch[0]);
            if (save_rcx && (base == REGISTER_RCX || index == REGISTER_RCX))
                emitRESTORE(stream, 0x50, REGISTER_RCX);
            if (save_rdx && (base == REGISTER_RDX || index == REGISTER_RDX))
                emitRESTORE(stream, 0x58, REGISTER_RDX);
        }

        check_no++;

        if (REDFAT_XLOWFAT && base != REGISTER_NONE && entry.lowfat)
        {
            emitLEA(stream, I, ub, regC);
            off_t adjust = 0x0;
            auto i = adjusts.find(base);
            if (i != adjusts.end())
                adjust = i->second;
            if (save_rcx && base == regC)
            {
                emitRESTORE(stream, 0x50, regPtr);
                emitADJUST(stream, adjust, regPtr, regPtr);
            }
            else
                emitADJUST(stream, adjust, base, regPtr);
            emitIDX(stream, regC, regIdx);
            emitMUL(stream, TABLE_MAGICS, regIdx, regPtr, regPtr);
            emitXCHG(stream, regC, regPtr);
            if (REDFAT_OELIM && index == REGISTER_NONE)
            {
                // regPtr must also be non-fat:
                emitJMP_IF_PASS(stream, check_no);
            }
            else
            {
                fprintf(stream, "%u,{\"rel8\":\".Lbase_nonfat_%d\"},",
                    0xe3, check_no);
                fprintf(stream, "%u,{\"rel8\":\".Lbase_lowfat_%d\"},",
                    0xeb, check_no);
                fprintf(stream, "\".Lbase_nonfat_%d\",", check_no);
                emitMUL(stream, TABLE_MAGICS, regIdx, regC, regC);
                emitJMP_IF_PASS(stream, check_no);
                fprintf(stream, "\".Lbase_lowfat_%d\",", check_no);
            }
        }
        else
        {
            emitLEA(stream, I, ub, regPtr);
            emitIDX(stream, regPtr, regIdx);
            emitMUL(stream, TABLE_MAGICS, regIdx, regC, regC);
            emitJMP_IF_PASS(stream, check_no);
        }

        emitXCHG(stream, regC, regPtr);

        Register regScratch1 = regScratch[1];
        bool save_scratch_1 = false;
        if (REDFAT_XSIZE)
        {
            // For XSIZE we need an additional scratch register, so allocate
            // it here:
            if (regScratch1 == REGISTER_INVALID)
            {
                save_scratch_1 = true;
                regScratch1 =
                    (regScratch[0] == REGISTER_RBX? REGISTER_RDI: REGISTER_RBX);
                emitSAVE(stream, 0x60, regScratch1);
                regScratch1 = regScratch1;
            }
            emitLOAD(stream, TABLE_SIZES, regIdx, regScratch1);
            emitMUL(stream, regScratch1, regPtr, regIdx);
        }
        else
        {
            emitMUL(stream, TABLE_SIZES, regIdx, regPtr, regIdx);
        }

        // Rename for "clarity":
        Register regBase = regPtr;
        Register regSizePtr = regBase;
        regPtr = regC;

        if (REDFAT_XPROFILE)
        {
            if (!clobberFlags)
            {
                emitSAVE(stream, 0x68, REGISTER_RAX);
                fprintf(stream, "%u,%u,%u,", 0x0f, 0x90, 0xc0);
                fprintf(stream, "%u,", 0x9f);
            }
    
            // lock add $size,PROFILE
            if (entry.read && entry.redzone)
                fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                    0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_REDZONE_READ_NONLEGACY_CHECKS),
                    1);
            if (!entry.read && entry.redzone)
                fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                    0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_REDZONE_WRITE_NONLEGACY_CHECKS),
                    1);
            if (entry.read && entry.lowfat)
                fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                    0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_LOWFAT_READ_NONLEGACY_CHECKS),
                    1);
            if (!entry.read && entry.lowfat)
                fprintf(stream, "%u,%u,%u,%u,%u,{\"int32\":%d},{\"int8\":%d},",
                    0xf0, 0x48, 0x83, 0x04, 0x25,
            REDFAT_PROFILE_VAR(REDFAT_PROFILE_LOWFAT_WRITE_NONLEGACY_CHECKS),
                    1);
            if (!clobberFlags)
            {
                fprintf(stream, "%u,%u,", 0x04, 0x7f);
                fprintf(stream, "%u,", 0x9e);
                emitRESTORE(stream, 0x68, REGISTER_RAX);
            }
        }

        if (clobberFlags)
        {
            // We are allowed to clobber the %rflags register, so we can use
            // normal arithmetic functions:

            if (REDFAT_XSIZE)
            {
                emitADD(stream, /*r64=*/false, -16, regScratch1);
            }

            // diff := ptr - base
            Register regDiff = regPtr;
            emitSUB(stream, regBase, regDiff);

            // diff := ptr - (base + 16) - delta
            emitADD(stream, /*r64=*/false, -(delta + 16), regDiff);

            // diff = ptr - (base + 16)
            emitADD(stream, /*r64=*/true, delta, regDiff);

            // NOTE: the previous two instructions cannot be merged.  The
            //       former generates a 32bit result, while the latter is
            //       64bit.  The point is to detect bounds underflows using
            //       integer underflows, which works with the above setup.

            // PTR CHECK (diff <= size)
            emitDEREF_CMP(stream, regSizePtr, regDiff);

            fprintf(stream, "%u,{\"rel8\":\".Lpassed_PTR_%d\"},", 0x76,
                check_no);
            emitABORT(stream);
            fprintf(stream, "\".Lpassed_PTR_%d\",", check_no);

            if (REDFAT_XSIZE)
            {
                emitCMP(stream, regScratch1, regDiff);

                fprintf(stream, "%u,{\"rel8\":\".Lpassed_SIZE_%d\"},", 0x76,
                    check_no);
                emitABORT(stream);
                fprintf(stream, "\".Lpassed_SIZE_%d\",", check_no);
            }
        }
        else
        {
            // We are not allowed to clobber the %rflags register, so we are
            // restricted to using LEA and other instructions that do not
            // modify the flags.

            // size = *base0
            Register regSize = regIdx;
            emitDEREF(stream, regSizePtr, regSize);

            // base1 := -base0 - 1
            emitNOT(stream, regBase);

            // diff0 := ptr - (base0 + 16) - delta
            Register regDiff = regBase;
            emitADD(stream, /*r64=*/false, -delta - 16 + 1, regPtr, regBase,
                regDiff);

            // diff1 := -(ptr - (base0 + 16)) + delta - 1
            emitNOT(stream, regDiff);

            // diff2 := size - (ptr - (base0 + 16))
            emitADD(stream, /*r64=*/true, -delta + 1, regSize, regDiff, regC);

            // PTR CHECK (diff2 < 0)
            emitSWAP(stream, regC, regC);
            fprintf(stream, "%u,%u,{\"rel8\":\".Lpassed_PTR_%d\"},",
                0x67, 0xe3, check_no);
            emitABORT(stream);
            fprintf(stream, "\".Lpassed_PTR_%d\",", check_no);

            if (REDFAT_XSIZE)
            {
                // diff2' := (lowFatSize - 16) - (ptr - (base0 + 16))
                emitADD(stream, /*r64=*/true, -16 - delta + 1, regScratch1,
                    regDiff, regC);

                emitSWAP(stream, regC, regC);
                fprintf(stream, "%u,%u,{\"rel8\":\".Lpassed_SIZE_%d\"},",
                    0x67, 0xe3, check_no);
                emitABORT(stream);
                fprintf(stream, "\".Lpassed_SIZE_%d\",", check_no);
            }
        }

        if (save_scratch_1)
            emitRESTORE(stream, 0x60, regScratch1);

        fprintf(stream, "\".Lpassed_%d\",", check_no);
    }

    if (save_scratch)
        emitRESTORE(stream, 0x70, regScratch[0]);
    if (save_rcx)
        emitRESTORE(stream, 0x50, REGISTER_RCX);
    if (save_rdx)
        emitRESTORE(stream, 0x58, REGISTER_RDX);
}

/*************************************************************************/
/* ALLOWLIST                                                             */
/*************************************************************************/

/*
 * Parse an allowlist.
 */
static void readAllowlist(const char *filename)
{
    FILE *stream = fopen(filename, "r");
    if (stream == nullptr)
        error("failed to open allowlist \"%s\": %s", optarg,
            strerror(errno));
    allowlist.clear();
    while (true)
    {
        char c;
        while (isspace(c = getc(stream)) && c != EOF && c != '#')
            ;
        switch (c)
        {
            case EOF:
                fclose(stream);
                return;
            case '#':
                while ((c = getc(stream)) != '\n' && c != EOF)
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
            buf[i] = getc(stream);
            if (buf[i] == EOF)
            {
                fclose(stream);
                return;
            }
            if (isspace(buf[i]))
                break;
        }
        buf[i] = '\0';
        intptr_t addr = strtoull(buf, NULL, 0);
        while (isspace(c = getc(stream)) && c != EOF)
            ;
        int8_t allow = 0;
        switch (c)
        {
            case '0': case '1': case '2': case '3':
                allow = c - '0';
                break;
            default:
                error("failed to parse allow-list \"%s\"", filename);
        }
        log("%lx: %s\n", addr,
            (allow == ALLOW_REDZONE? "\33[31mLOWFAT-UNSAFE\33[0m":
            (allow == ALLOW_LOWFAT?  "\33[32mLOWFAT-SAFE\33[0m":
            (allow == ALLOW_NONFAT?  "\33[33mNONFAT-ONLY\33[0m":
                "NOT-REACHED"))));
        allowlist.insert({addr, allow});
    }
}

/*
 * Write an allowlist.
 */
static void writeAllowlist(RedFat *cxt, const char *filename)
{
    FILE *stream = fopen(filename, "w");
    if (stream == nullptr)
        error("failed to open allowlist \"%s\": %s", optarg,
            strerror(errno));
    fputs("# RedFat ALLOWLIST (uninitialized)\n", stream);
    fputs("# 0 = Redzone-only\n", stream);
    fputs("# 1 = Lowfat+Redzone\n", stream);
    fputs("# 2 = Nonfat\n", stream);
    fputs("# 3 = Not reached\n\n", stream);
    for (const auto &batch: cxt->batches)
        for (const auto &entry: batch.second.entries)
            fprintf(stream, "0x%lx 3\n", entry.I->address);
    fclose(stream);
}

/*************************************************************************/
/* ELF CHECKS                                                            */
/*************************************************************************/

/*
 * Check if the binary is compatible with RedFat.
 */
static void checkBinary(const ELF *elf)
{
    const uint8_t *data = getELFData(elf);
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    size_t phnum = (size_t)ehdr->e_phnum;
    const Elf64_Dyn *dynamic = nullptr;
    for (size_t i = 0; dynamic == nullptr && i < phnum; i++)
    {
        if (phdrs[i].p_type == PT_DYNAMIC)
            dynamic = (const Elf64_Dyn *)(data + phdrs[i].p_offset);
    }
    if (dynamic == nullptr)
        error("binary \"%s\" is not dynamically linked\n"
            "         (LD_PRELOAD will not work)\n"
            "         Use `-force' to instrument anyway",
            getELFFilename(elf));
    const SymbolInfo &dynsym = getELFDynSymInfo(elf);

    /*
     * If the binary exports its own malloc(), then the dynamic linker will
     * use it and ignore the LD_PRELOAD version.
     */
    const char *funcs[] =
    {
        "malloc", "calloc", "realloc", "free",
        "_Znam", "_ZnamRKSt9nothrow_t", "_Znwm", "_ZnwmRKSt9nothrow_t",
        "_ZdaPv", "_ZdlPv", nullptr
    };
    for (size_t i = 0; funcs[i] != nullptr; i++)
    {
        auto j = dynsym.find(funcs[i]);
        if (j == dynsym.end())
            continue;
        const Elf64_Sym *sym = j->second;
        if (sym->st_shndx == SHN_UNDEF)
            continue;
        switch (ELF64_ST_TYPE(sym->st_info))
        {
            case STT_FUNC: case STT_GNU_IFUNC:
                error("binary \"%s\" exports a custom \"%s\" function\n"
                    "         (LD_PRELOAD may not work)\n"
                    "         Use `-force' to instrument anyway",
                    getELFFilename(elf), funcs[i]);
            default:
                break;
        }
    }
}

/*************************************************************************/
/* E9TOOL INTERFACE                                                      */
/*************************************************************************/

enum Option
{
    OPTION_XREADS,
    OPTION_XWRITES,
    OPTION_XLOWFAT,
    OPTION_XSTACK,
    OPTION_XFRAME,
    OPTION_XGLOBALS,
    OPTION_XSIZE,
    OPTION_XADJUST,
    OPTION_XDEBUG,
    OPTION_XPROFILE,
    OPTION_OELIM,
    OPTION_OBATCH,
    OPTION_OSCRATCH,
    OPTION_OMERGE,
    OPTION_OFLAGS,
    OPTION_OSTACK,
    OPTION_OFRAME,
    OPTION_OGLOBALS,
    OPTION_OSYSV,
    OPTION_XALLOWLIST_GEN,
    OPTION_XALLOWLIST_USE,
    OPTION_XALLOWLIST_MODE,
    OPTION_FORCE,
    OPTION_LOG,
    OPTION_PATH,
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

/*
 * Initialization.
 */
extern void *e9_plugin_init(const Context *context)
{
    static const struct option long_options[] =
    {
        {"Xlowfat",        optional_argument, nullptr, OPTION_XLOWFAT},
        {"Xreads",         optional_argument, nullptr, OPTION_XREADS},
        {"Xwrites",        optional_argument, nullptr, OPTION_XWRITES},
        {"Xstack",         optional_argument, nullptr, OPTION_XSTACK},
        {"Xframe",         optional_argument, nullptr, OPTION_XFRAME},
        {"Xglobals",       optional_argument, nullptr, OPTION_XGLOBALS},
        {"Xsize",          optional_argument, nullptr, OPTION_XSIZE},
        {"Xadjust",        optional_argument, nullptr, OPTION_XADJUST},
        {"Xdebug",         optional_argument, nullptr, OPTION_XDEBUG},
        {"Xprofile",       optional_argument, nullptr, OPTION_XPROFILE},
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
        {"Oglobals",       optional_argument, nullptr, OPTION_OGLOBALS},
        {"Osysv",          optional_argument, nullptr, OPTION_OSYSV},
        {"force",          optional_argument, nullptr, OPTION_FORCE},
        {"log",            optional_argument, nullptr, OPTION_LOG},
        {"path",           required_argument, nullptr, OPTION_PATH},
        {nullptr,          no_argument,       nullptr, 0}
    };

    std::string option_path(".");
    bool option_xdebug = false;
    char * const *argv = context->argv->data();
    int argc = (int)context->argv->size();
    optind = 1;
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "Po:v", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_XLOWFAT:
                REDFAT_XLOWFAT = strToBool(optarg);
                break;
            case OPTION_XREADS:
                REDFAT_XREADS = strToBool(optarg);
                break;
            case OPTION_XWRITES:
                REDFAT_XWRITES = strToBool(optarg);
                break;
            case OPTION_XSTACK:
                REDFAT_XSTACK = strToBool(optarg);
                break;
            case OPTION_XFRAME:
                REDFAT_XFRAME = strToBool(optarg);
                break;
            case OPTION_XGLOBALS:
                REDFAT_XGLOBALS = strToBool(optarg);
                break;
            case OPTION_XSIZE:
                REDFAT_XSIZE = strToBool(optarg);
                break;
            case OPTION_XADJUST:
                REDFAT_XADJUST = strToBool(optarg);
                break;
            case OPTION_XDEBUG:
                option_xdebug = strToBool(optarg);
                break;
            case OPTION_XPROFILE:
                REDFAT_XPROFILE = strToBool(optarg);
                break;
            case OPTION_XALLOWLIST_GEN:
                REDFAT_XALLOWLIST_GEN = true;
                REDFAT_XALLOWLIST = optarg;
                break;
            case OPTION_XALLOWLIST_USE:
                REDFAT_XALLOWLIST_USE = true;
                REDFAT_XALLOWLIST = optarg;
                readAllowlist(REDFAT_XALLOWLIST);
                break;
            case OPTION_XALLOWLIST_MODE:
            {
                unsigned i;
                for (i = 0; i < 4; i++)
                {
                    switch (optarg[i])
                    {
                        case 'R':
                            REDFAT_XALLOWLIST_MODE[i] = MODE_REDZONE;
                            break;
                        case 'L':
                            REDFAT_XALLOWLIST_MODE[i] = MODE_LOWFAT;
                            break;
                        case '-':
                            REDFAT_XALLOWLIST_MODE[i] = MODE_NONE;
                            break;
                        case '\0':
                        invalid_mode_length:
                            error("failed to parse allow-list mode \"%s\"; "
                                "invalid length (%zu), expected 4",
                                optarg, strlen(optarg));
                        default:
                            error("failed to parse allow-list mode \"%s\"; "
                                "invalid mode element `%c', expected one of "
                                "{R,L,-}",
                                optarg, optarg[i]);
                    }
                }
                if (optarg[i] != '\0')
                    goto invalid_mode_length;
                break;
            }
            case OPTION_OELIM:
                REDFAT_OELIM = strToBool(optarg);
                break;
            case OPTION_OBATCH:
                REDFAT_OBATCH = strToInt(optarg);
                REDFAT_OBATCH = (REDFAT_OBATCH < 1 || REDFAT_OBATCH > 99? 1:
                    REDFAT_OBATCH);
                break;
            case OPTION_OMERGE:
                REDFAT_OMERGE = strToBool(optarg);
                break;
            case OPTION_OSCRATCH:
                REDFAT_OSCRATCH = strToBool(optarg);
                break;
            case OPTION_OFLAGS:
                REDFAT_OFLAGS = strToBool(optarg);
                break;
            case OPTION_OSTACK:
                REDFAT_OSTACK = strToBool(optarg);
                break;
            case OPTION_OFRAME:
                REDFAT_OFRAME = strToBool(optarg);
                break;
            case OPTION_OGLOBALS:
                REDFAT_OGLOBALS = strToBool(optarg);
                break;
            case OPTION_OSYSV:
                REDFAT_OSYSV = strToBool(optarg);
                break;
            case OPTION_FORCE:
                REDFAT_FORCE = strToBool(optarg);
                break;
            case OPTION_LOG:
                REDFAT_LOG = strToBool(optarg);
                break;
            case OPTION_PATH:
                option_path = optarg;
                break;
            default:
                error("invalid command-line options for %s", argv[0]);
        }
    }
    if (REDFAT_XALLOWLIST_GEN && REDFAT_XALLOWLIST_USE)
        error("option `-Xallowlist-gen' cannot be used with "
            "`-Xallowlist-use'");

    // Check if the binary is compatible.
    if (!REDFAT_FORCE)
        checkBinary(context->elf);

    // Reserve memory used by the RedFat runtime:
    const SectionInfo &sections = getELFSectionInfo(context->elf);
    intptr_t max = 0x0;
    for (const auto &entry: sections)
    {
        const Elf64_Shdr *section = entry.second;
        intptr_t end = (intptr_t)section->sh_addr + section->sh_size;
        max = std::max(max, end);
    }
    intptr_t rt_addr = (option_xdebug || REDFAT_XALLOWLIST_GEN?
        /*XXX=*/0x70000000: max + 0x10000000);
    rt_addr -= rt_addr % REDFAT_PAGE_SIZE;
    intptr_t config_addr = rt_addr - REDFAT_PAGE_SIZE;
    struct redfat redfat = {0};
    if (REDFAT_XALLOWLIST_GEN)
    {
        redfat.flags |= REDFAT_FLAG_ALLOWLIST_GEN;
        size_t len = strlen(REDFAT_XALLOWLIST);
        if (len >= sizeof(redfat.filename.allowlist)-1)
            error("allowlist filename \"%s\" is too long", REDFAT_XALLOWLIST);
        memcpy(redfat.filename.allowlist, REDFAT_XALLOWLIST, len+1);
    }
    if (REDFAT_XALLOWLIST_USE)
        redfat.flags |= REDFAT_FLAG_ALLOWLIST_USE;
    if (REDFAT_XPROFILE)
        redfat.flags |= REDFAT_FLAG_PROFILE;
    sendReserveMessage(context->out, config_addr,
        (const uint8_t *)&redfat, sizeof(redfat), PROT_READ,
        0x0, 0x0, 0x0, /*absolute=*/false);

    // Reserve memory used by the LowFat runtime:
    sendReserveMessage(context->out, TABLE_SIZES, TABLE_SIZE,
        /*absolute=*/true);
    sendReserveMessage(context->out, TABLE_MAGICS, TABLE_SIZE,
        /*absolute=*/true);

    // Send the RedFat runtime:
    if (!option_xdebug && !REDFAT_XALLOWLIST_GEN)
    {
        std::string path;
        path += option_path;
        path += "/redfat-rt";
        const ELF *rt = parseELF(path.c_str(), rt_addr);
        sendELFFileMessage(context->out, rt);
    }

    return (void *)(new RedFat);
}

/*************************************************************************/
/* ANALYSIS                                                              */
/*************************************************************************/

/*
 * Get the index of the next instruction, else SIZE_MAX
 */
static size_t nextInstr(const RedFat *cxt, size_t i)
{
    if (i >= cxt->size)
        return SIZE_MAX;
    if (cxt->Is[i].address + cxt->Is[i].size != cxt->Is[i+1].address)
        return SIZE_MAX;
    return i+1;
}

/*
 * Get the index of the previous instruction, else -1.
 */
static ssize_t prevInstr(const RedFat *cxt, ssize_t i)
{
    if (i <= 0)
        return -1;
    if (cxt->Is[i-1].address + cxt->Is[i-1].size != cxt->Is[i].address)
        return -1;
    return i-1;
}

/*
 * Analyze flags register.
 */
static bool analyzeFlags(const RedFat *cxt, intptr_t addr)
{
    std::set<intptr_t> seen;
    for (size_t i = findInstr(cxt->Is, cxt->size, addr); i < cxt->size; )
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(cxt->elf, cxt->Is + i, I);
        auto j = seen.insert(I->address);
        if (!j.second)
            return true;            // Loop detected.

        if (I->flags.read != 0x0)
            return false;           // %rflags read by instruction
        if ((I->flags.write & FLAG_ALL) == FLAG_ALL)
            return true;            // %rflags is clobbered.

        switch (I->mnemonic)
        {
            case MNEMONIC_CALL:
                if (REDFAT_OSYSV)
                    return true;    // SysV = calls clobber %rflags
                // Fallthrough:
            case MNEMONIC_JMP:
                if (I->op[0].type == OPTYPE_IMM)
                {
                    intptr_t target =
                        I->op[0].imm + I->address + (intptr_t)I->size;
                    i = findInstr(cxt->Is, cxt->size, target);
                    continue;
                }
                // Fallthrough:
            case MNEMONIC_RET:
                if (I->mnemonic == MNEMONIC_RET && REDFAT_OSYSV)
                    return true;    // SysV = assume callee ignores %rflags
                // Fallthrough:
            case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
            case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
            case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
            case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
            case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
            case MNEMONIC_JG: case MNEMONIC_JRCXZ: case MNEMONIC_JECXZ:
                return false;
            default:
                break;
        }
        i = nextInstr(cxt, i);
    }
    return false;
}

/*
 * Analyze scratch regsiters.
 */
static void analyzeScratch(const RedFat *cxt, uintptr_t addr, RegSet &scratch)
{
    std::set<intptr_t> seen;
    RegSet used;
    used.add(REGISTER_RSP);
    for (size_t i = findInstr(cxt->Is, cxt->size, addr); i < cxt->size; )
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(cxt->elf, cxt->Is + i, I);
        auto j = seen.insert(I->address);
        if (!j.second)
            break;

        for (uint8_t j = 0; I->regs.read[j] != REGISTER_INVALID; j++)
            used.add(I->regs.read[j]);
        for (uint8_t j = 0; I->regs.condread[j] != REGISTER_INVALID; j++)
            used.add(I->regs.condread[j]);
        for (uint8_t j = 0; I->regs.write[j] != REGISTER_INVALID; j++)
        {
            if (!regClobbered(I->regs.write[j]) ||
                    used.member(I->regs.write[j]))
                continue;
            scratch.add(I->regs.write[j]);
        }

        switch (I->mnemonic)
        {
            case MNEMONIC_CALL:
                if (REDFAT_OSYSV)
                {
                    const Register rargs[] =
                    {
                        REGISTER_RDI, REGISTER_RSI, REGISTER_RDX,
                        REGISTER_RCX, REGISTER_R8, REGISTER_R9,
                        REGISTER_INVALID
                    };
                    const Register rclobbers[] =
                    {
                        REGISTER_RAX, REGISTER_R10, REGISTER_R11,
                        REGISTER_INVALID
                    };
                    for (uint8_t j = 0; rargs[j] != REGISTER_INVALID; j++)
                        used.add(rargs[j]);
                    for (uint8_t j = 0; rclobbers[j] != REGISTER_INVALID; j++)
                    {
                        if (!used.member(rclobbers[j]))
                            scratch.add(rclobbers[j]);
                    }
                }
                // Fallthrough:
            case MNEMONIC_JMP:
                if (I->op[0].type == OPTYPE_IMM)
                {
                    intptr_t target =
                        I->op[0].imm + I->address + (intptr_t)I->size;
                    i = findInstr(cxt->Is, cxt->size, target);
                    continue;
                }
                // Fallthrough:
            case MNEMONIC_RET:
            case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
            case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
            case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
            case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
            case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
            case MNEMONIC_JG: case MNEMONIC_JRCXZ: case MNEMONIC_JECXZ:
                return;
            default:
                break;
        }
        i = nextInstr(cxt, i);
    }
}

/*
 * Analyze adjustment.
 */
static void analyzeAdjustments(const RedFat *cxt, uintptr_t addr,
    Adjusts &adjusts)
{
    if (cxt->targets.find(addr) != cxt->targets.end())
        return;
    RegSet clobbers;
    for (ssize_t i = findInstr(cxt->Is, cxt->size, addr) - 1; i >= 0;
            i = prevInstr(cxt, i))
    {
        if (cxt->targets.find(cxt->Is[i].address) != cxt->targets.end())
            return;
        InstrInfo I0, *I = &I0;
        getInstrInfo(cxt->elf, cxt->Is + i, I);
        switch (I->mnemonic)
        {
            case MNEMONIC_ADD:
                if (I->count.op == 2 && I->op[0].type == OPTYPE_IMM &&
                    I->op[1].type == OPTYPE_REG && regno(I->op[1].reg) > 0 &&
                    I->op[1].size == sizeof(void *) &&
                    !clobbers.member(I->op[1].reg))
                {
                    adjusts.insert({I->op[1].reg, -(off_t)I->op[0].imm});
                }
                break;
            case MNEMONIC_LEA:
                if (I->count.op == 2 && I->op[0].type == OPTYPE_MEM &&
                    I->op[0].size == sizeof(void *) &&
                    I->op[1].type == OPTYPE_REG && regno(I->op[1].reg) > 0 &&
                    I->op[1].size == sizeof(void *) &&
                    I->op[0].mem.seg == REGISTER_NONE &&
                    I->op[0].mem.base == I->op[1].reg &&
                    I->op[0].mem.index == REGISTER_NONE &&
                    I->op[0].mem.scale == 1)
                {
                    adjusts.insert({I->op[1].reg, -(off_t)I->op[1].mem.disp});
                }
                break;
            case MNEMONIC_CALL: case MNEMONIC_JMP: case MNEMONIC_RET:
            case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
            case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
            case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
            case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
            case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
            case MNEMONIC_JG: case MNEMONIC_JRCXZ: case MNEMONIC_JECXZ:
                return;
            default:
                break;
        }
        for (uint8_t j = 0; I->regs.write[j] != REGISTER_INVALID; j++)
            clobbers.add(I->regs.write[j]);
        for (uint8_t j = 0; I->regs.condwrite[j] != REGISTER_INVALID; j++)
            clobbers.add(I->regs.condwrite[j]);
    }
}

/*
 * Optimize the current batch.
 */
static void optimizeBatch(RedFat *cxt)
{
    std::vector<InstrInfo> Is;
    for (const auto &entry: cxt->batch)
    {
        Is.emplace_back();
        InstrInfo *I = &Is.back();
        getInstrInfo(cxt->elf, entry.I, I);
    }

    size_t batch_size = cxt->batch.size();
    for (size_t i = 0; i < batch_size; i++)
    {
        BatchEntry &entry = cxt->batch[i];
        InstrInfo *I = &Is[i];
        const OpInfo *memOp = getMemOp(I);
        int32_t disp  = memOp->mem.disp;
        uint8_t scale = memOp->mem.scale;
        Register base = memOp->mem.base, index = memOp->mem.index;
        if (REDFAT_OMERGE)
        {
            for (size_t j = 0; j < i; j++)
            {
                if (cxt->batch[j].removed)
                    continue;
                InstrInfo *J = &Is[j];
                memOp = getMemOp(J);
                if (base == memOp->mem.base && index == memOp->mem.index &&
                        scale == memOp->mem.scale)
                {
                    // Merge with existing entry.
                    cxt->batch[j].redzone =
                        (cxt->batch[j].redzone && cxt->batch[i].redzone);
                    cxt->batch[j].lowfat =
                        (cxt->batch[j].lowfat && cxt->batch[i].lowfat);
                    cxt->batch[j].lb = std::min(entry.lb, cxt->batch[j].lb);
                    cxt->batch[j].ub = std::max(entry.ub, cxt->batch[j].ub);
                    cxt->batch[i].removed = true;
                    break;
                }
            }
        }
    }

    for (ssize_t i = 0; i < batch_size; i++)
    {
        InstrInfo *I = &Is[i];
        if (cxt->batch[i].removed)
        {
            log("\t%lx: %s [\33[31mMERGE\33[0m]\n", I->address,
                I->string.instr);
            continue;
        }
        BatchEntry &entry = cxt->batch[i];
        log("\t%lx: %s [%s%#zx..%s%#zx]\n", I->address,
            I->string.instr, (entry.lb < 0? "-": ""), std::abs(entry.lb),
            (entry.ub < 0? "-": ""), std::abs(entry.ub));
    }
}

/*
 * Flush the current batch.
 */
static void flushBatch(RedFat *cxt)
{
    cxt->clobbered.clear();
    if (cxt->batch.size() == 0)
    {
        // Nothing to flush...
        return;
    }

    cxt->batches_num++;
    cxt->batches_size += cxt->batch.size();

    double avg = (double)cxt->batches_size / (double)cxt->batches_num;
    log("\33[33mBATCH\33[0m SIZE=%zu (%.2f)\n", cxt->batch.size(), avg);
    optimizeBatch(cxt);

    const Instr *I = cxt->batch.front().I;
    Batch empty;
    auto i = cxt->batches.insert({I->address, empty});

    Batch &newBatch = i.first->second;
    cxt->batch.swap(newBatch.entries);
    newBatch.clobber_flags =
        (REDFAT_OFLAGS? analyzeFlags(cxt, I->address): false);
    if (REDFAT_OSCRATCH)
        analyzeScratch(cxt, I->address, newBatch.scratch);
    if (REDFAT_XADJUST)
        analyzeAdjustments(cxt, I->address, newBatch.adjusts);

    log("\t%lx: scratch = ", I->address);
    newBatch.scratch.dump();
    log('\n');
    log("\t%lx: flags = %s\n", I->address,
        (newBatch.clobber_flags? "clobber": "used"));
    log("\t%lx: adjusts = {", I->address);
    bool prev = false;
    for (const auto &entry: newBatch.adjusts)
    {
        if (prev)
            log(',');
        log("%s:%+zd", regName(entry.first), entry.second);
        prev = true;
    }
    log("}\n");
}

/*
 * Get the memory operand.
 */
static const OpInfo *getMemOp(const InstrInfo *I)
{
    const OpInfo *memOp = nullptr;
    for (uint8_t i = 0; memOp == nullptr && i < I->count.op; i++)
    {
        const OpInfo *op = I->op + i;
        if (op->type != OPTYPE_MEM)
            continue;
        if (op->mem.seg == REGISTER_FS || op->mem.seg == REGISTER_GS)
            continue;
        switch (op->mem.base)
        {
            case REGISTER_RIP:
                continue;
            case REGISTER_NONE:
                if (!REDFAT_XGLOBALS || REDFAT_XALLOWLIST_GEN)
                    continue;
                if (REDFAT_OELIM && REDFAT_OGLOBALS &&
                        op->mem.index == REGISTER_NONE)
                    continue;
                break;
            case REGISTER_RSP:
                if (!REDFAT_XSTACK)
                    continue;
                if (REDFAT_OELIM && REDFAT_OSTACK &&
                        op->mem.index == REGISTER_NONE)
                    continue;
                break;
            case REGISTER_RBP:
                if (!REDFAT_XFRAME)
                    continue;
                if (REDFAT_OELIM && REDFAT_OFRAME &&
                        op->mem.index == REGISTER_NONE)
                    continue;
                break;
            default:
                break;
        }
        switch (op->mem.base)
        {
            case REGISTER_RAX: case REGISTER_RCX: case REGISTER_RDX:
            case REGISTER_RBX: case REGISTER_RSP: case REGISTER_RBP:
            case REGISTER_RSI: case REGISTER_RDI: case REGISTER_R8:
            case REGISTER_R9: case REGISTER_R10: case REGISTER_R11:
            case REGISTER_R12: case REGISTER_R13: case REGISTER_R14:
            case REGISTER_R15: case REGISTER_RIP: case REGISTER_NONE:
            case REGISTER_EAX: case REGISTER_ECX: case REGISTER_EDX:
            case REGISTER_EBX: case REGISTER_ESP: case REGISTER_EBP:
            case REGISTER_ESI: case REGISTER_EDI: case REGISTER_R8D:
            case REGISTER_R9D: case REGISTER_R10D: case REGISTER_R11D:
            case REGISTER_R12D: case REGISTER_R13D: case REGISTER_R14D:
            case REGISTER_R15D: case REGISTER_EIP:
                break;
            default:
                continue;
        }
        switch (op->mem.index)
        {
            case REGISTER_RAX: case REGISTER_RCX: case REGISTER_RDX:
            case REGISTER_RBX: case REGISTER_RSP: case REGISTER_RBP:
            case REGISTER_RSI: case REGISTER_RDI: case REGISTER_R8:
            case REGISTER_R9: case REGISTER_R10: case REGISTER_R11:
            case REGISTER_R12: case REGISTER_R13: case REGISTER_R14:
            case REGISTER_R15: case REGISTER_NONE: case REGISTER_EAX:
            case REGISTER_ECX: case REGISTER_EDX: case REGISTER_EBX:
            case REGISTER_ESP: case REGISTER_EBP: case REGISTER_ESI:
            case REGISTER_EDI: case REGISTER_R8D: case REGISTER_R9D:
            case REGISTER_R10D: case REGISTER_R11D: case REGISTER_R12D:
            case REGISTER_R13D: case REGISTER_R14D: case REGISTER_R15D:
                break;
            default:
                // Unsupported, e.g., scatter/gather
                continue;
        }
        memOp = op;
    }
    switch (I->mnemonic)
    {
        case MNEMONIC_NOP: case MNEMONIC_LEA:
            // These instructions do not access the memory operand.
            memOp = nullptr;
            break;
        case MNEMONIC_PREFETCH: case MNEMONIC_PREFETCHNTA:
        case MNEMONIC_PREFETCHT0: case MNEMONIC_PREFETCHT1:
        case MNEMONIC_PREFETCHT2: case MNEMONIC_PREFETCHW:
        case MNEMONIC_PREFETCHWT1:
        case MNEMONIC_VPREFETCH0: case MNEMONIC_VPREFETCH1:
        case MNEMONIC_VPREFETCH2: case MNEMONIC_VPREFETCHE0:
        case MNEMONIC_VPREFETCHE1: case MNEMONIC_VPREFETCHE2:
        case MNEMONIC_VPREFETCHENTA: case MNEMONIC_VPREFETCHNTA:
            // These instructions do not (really) access the memory operand.
            memOp = nullptr;
            break;
        default:
            break;
    }
    if (I->encoding.offset.modrm < 0)
    {
        // TODO: Currently we only protect instructions that use ModR/M
        memOp = nullptr;
    }
    if (I->data[0] == /*lock prefix=*/0xF0)
    {
        // Some binaries (like glibc) use the jump-over-the-lock trick, which
        // is currently not compatible with E9Patch
        memOp = nullptr;
    }
    return memOp;
}

/*
 * Analyze batched memory acccess.
 */
static void analyzeBatches(RedFat *cxt)
{
    for (size_t i = 0; i < cxt->size; i++)
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(cxt->elf, cxt->Is + i, I);

        auto j = cxt->targets.find(I->address);
        if (j != cxt->targets.end())
        {
            // Jump/call target == flush
            flushBatch(cxt);
        }

        const OpInfo *memOp = getMemOp(I);
        bool read  = (memOp != nullptr && (memOp->access & ACCESS_READ) != 0),
             write = (memOp != nullptr && (memOp->access & ACCESS_WRITE) != 0);
        bool check = (REDFAT_XWRITES? write: false) ||
                     (REDFAT_XREADS?  read: false);
        if (!check)
            memOp = nullptr;

        if (memOp != nullptr &&
            (cxt->clobbered.member(memOp->mem.base) ||
            (memOp->mem.index != REGISTER_NONE &&
             cxt->clobbered.member(memOp->mem.index))))
        {
            // We need to instrument this instruction, but one of the base/index
            // has been clobbered.  So we must create a new batch:
            flushBatch(cxt);
        }
        else if (memOp != nullptr && cxt->batch.size() >= REDFAT_OBATCH)
        {
            // Current batch is too big!
            flushBatch(cxt);
        }

        bool lowfat = REDFAT_XLOWFAT;
        if (memOp != nullptr)
        {
            switch (allowlist_lookup(I))
            {
                case MODE_NONE:
                    memOp = nullptr;
                    break;
                case MODE_REDZONE:
                    lowfat = false;
                    break;
                case MODE_LOWFAT:
                    break;
            }
        }

        if (memOp != nullptr)
        {
            BatchEntry entry(cxt->Is + i, memOp->mem.disp,
                (ssize_t)memOp->mem.disp + memOp->size);
            entry.lowfat = lowfat;
            entry.read   = (memOp->access == ACCESS_READ);
            cxt->batch.push_back(entry);
        }

        // Update register clobbers:
        if (cxt->batch.size() > 0)
        {
            for (uint8_t j = 0; I->regs.write[j] != REGISTER_INVALID; j++)
                cxt->clobbered.add(I->regs.write[j]);
        }

        switch (I->mnemonic)
        {
            case MNEMONIC_CALL:
            case MNEMONIC_RET:
            case MNEMONIC_JMP:
            case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
            case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
            case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
            case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
            case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
            case MNEMONIC_JG: case MNEMONIC_JRCXZ: case MNEMONIC_JECXZ:
                // Control-flow transfer == flush
                flushBatch(cxt);
                break;
            default:
                break;
        }
    }

    flushBatch(cxt);
}

/*
 * Events.
 */
extern void e9_plugin_event(const Context *context, Event event)
{
    RedFat *cxt = (RedFat *)context->context;
    switch (event)
    {
        case EVENT_DISASSEMBLY_COMPLETE:
            cxt->elf  = context->elf;
            cxt->Is   = context->Is->data();
            cxt->size = context->Is->size();
            buildTargets(cxt->elf, cxt->Is, cxt->size, cxt->targets);
            analyzeBatches(cxt);
            break;
        case EVENT_MATCHING_COMPLETE:
            break;
        case EVENT_PATCHING_COMPLETE:
            if (REDFAT_XALLOWLIST_GEN)
                writeAllowlist(cxt, REDFAT_XALLOWLIST);
            delete cxt;
            break;
    }
}

/*
 * Matching.
 * (return `true' iff we should instrument this instruction)
 */
extern intptr_t e9_plugin_match(const Context *context)
{
    RedFat *cxt = (RedFat *)context->context;
    auto i = cxt->batches.find(context->I->address);
    return (i != cxt->batches.end());
}

/*
 * Patch template.
 */
extern void e9_plugin_code(const Context *context)
{
    fprintf(context->out, "\"$redfat\",");
}

/*
 * Patching.
 */
extern void e9_plugin_patch(const Context *context)
{
    RedFat *cxt = (RedFat *)context->context;
    auto i = cxt->batches.find(context->I->address);
    if (i == cxt->batches.end())
        error("no such batch for address 0x%lx", context->I->address);
    const Batch &batch = i->second;
    fprintf(context->out, "\"$redfat\":[");
    emitCHECK(context->out, cxt->elf, batch.entries, batch.adjusts,
        batch.scratch, batch.clobber_flags);
    fputc(']', context->out);
}

