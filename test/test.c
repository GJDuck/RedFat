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

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

typedef void (*test_func_t)(intptr_t, ssize_t);

struct test_s
{
    ssize_t lo;
    ssize_t hi;
    const char *name;
    test_func_t func;
    ssize_t disp;
    ssize_t scale;
    ssize_t size;
};

static intptr_t LB(const struct test_s *test, intptr_t ptr, ssize_t offset)
{
    return ptr + test->disp + test->scale * offset;
}
static intptr_t UB(const struct test_s *test, intptr_t ptr, ssize_t offset)
{
    return LB(test, ptr, offset) + test->size;
}
static bool OOB(const struct test_s *test, intptr_t lb, intptr_t ub,
    intptr_t ptr, ssize_t offset)
{
    return !(LB(test, ptr, offset) >= lb && UB(test, ptr, offset) <= ub);
}

static __attribute__((__noinline__)) void use(size_t x)
{
    asm ("": : "r"(x): "memory");
}
static __attribute__((__noinline__)) size_t unknown(size_t size)
{
    return size;
}

/*
 * Tests.
 */
static void read1x8c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("rbx") = offset;
    asm ("testb $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void read1x16c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("rcx") = offset;
    asm ("testw $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void read1x32c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("rdx") = offset;
    asm ("testl $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void read1x64c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("rbp") = offset;
    asm ("testq $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void read4x32c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("r9") = ptr;
    register ssize_t index asm("r10") = offset;
    asm ("testl $0x0,(%0,%1,1)\n"
         "testl $0x0,4(%0,%1,1)\n"
         "testl $0x0,8(%0,%1,1)\n"
         "testl $0x0,12(%0,%1,1)" : : "r"(base), "r"(index));
}
static void read1x8f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("rsi") = offset;
    asm ("movb (%0,%1,1),%%cl\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rcx");
}
static void read1x16f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("rdi") = offset;
    asm ("movw (%0,%1,1),%%cx\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rcx");
}
static void read1x32f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r8") = offset;
    asm ("movl (%0,%1,1),%%ecx\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rcx");
}
static void read1x64f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r9") = offset;
    asm ("movq (%0,%1,1),%%rcx\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rcx");
}
static void read4x32f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("r11") = ptr;
    register ssize_t index asm("r12") = offset;
    asm ("movl (%0,%1,1),%%ecx\n"
         "movl 4(%0,%1,1),%%ecx\n"
         "movl 8(%0,%1,1),%%ecx\n"
         "movl 12(%0,%1,1),%%ecx" : : "r"(base), "r"(index) : "rcx");
}
static void write1x8c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r10") = offset;
    asm ("andb $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void write1x16c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r11") = offset;
    asm ("andw $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void write1x32c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r12") = offset;
    asm ("andl $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void write1x64c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r13") = offset;
    asm ("andq $0x0,(%0,%1,1)" : : "r"(base), "r"(index));
}
static void write4x32c(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("r12") = ptr;
    register ssize_t index asm("r13") = offset;
    asm ("andl $0x0,(%0,%1,1)\n"
         "andl $0x0,4(%0,%1,1)\n"
         "andl $0x0,8(%0,%1,1)\n"
         "andl $0x0,12(%0,%1,1)" : : "r"(base), "r"(index));
}
static void write1x8f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r14") = offset;
    asm ("movb $0x0,(%0,%1,1)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write1x16f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    register ssize_t index asm("r15") = offset;
    asm ("movw $0x0,(%0,%1,1)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write1x32f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("rbx") = offset;
    asm ("movl $0x0,(%0,%1,1)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write1x64f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("rdx") = offset;
    asm ("movq $0x0,(%0,%1,1)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write4x32f(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("r14") = ptr;
    register ssize_t index asm("r15") = offset;
    asm ("movl $0x0,(%0,%1,1)\n"
         "movl $0x0,4(%0,%1,1)\n"
         "movl $0x0,8(%0,%1,1)\n"
         "movl $0x0,12(%0,%1,1)\n"
         "cmovne %0,%1": : "r"(base), "r"(index));
}
static void read1x8c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("rbp") = offset;
    asm ("testb $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void read1x16c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("rsi") = offset;
    asm ("testw $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void read1x32c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("rdi") = offset;
    asm ("testl $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void read1x64c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r8") = offset;
    asm ("testq $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void read1x8f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r9") = offset;
    asm ("movb 0x10(%0,%1,2),%%dl\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rdx");
}
static void read1x16f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r10") = offset;
    asm ("movw 0x10(%0,%1,2),%%dx\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rdx");
}
static void read1x32f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r11") = offset;
    asm ("movl 0x10(%0,%1,2),%%edx\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rdx");
}
static void read1x64f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r12") = offset;
    asm ("movq 0x10(%0,%1,2),%%rdx\n"
         "cmovne %0,%1" : : "r"(base), "r"(index) : "rdx");
}
static void write1x8c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r13") = offset;
    asm ("andb $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void write1x16c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r14") = offset;
    asm ("andw $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void write1x32c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    register ssize_t index asm("r15") = offset;
    asm ("andl $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void write1x64c2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("rbx") = offset;
    asm ("andq $0x0,0x10(%0,%1,2)" : : "r"(base), "r"(index));
}
static void write1x8f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("rax") = offset;
    asm ("movb $0x0,0x10(%0,%1,2)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write1x16f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("rbp") = offset;
    asm ("movw $0x0,0x10(%0,%1,2)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write1x32f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("rsi") = offset;
    asm ("movl $0x0,0x10(%0,%1,2)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void write1x64f2(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("rdi") = offset;
    asm ("movq $0x0,0x10(%0,%1,2)\n"
         "cmovne %0,%1" : : "r"(base), "r"(index));
}
static void sse1x128(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("r8") = offset;
    asm ("movdqa %%xmm0,-0x10(%0,%1,4)" : : "r"(base), "r"(index));
}
static void avx1x256(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    register ssize_t index asm("r9") = offset;
    asm ("vmovdqa %%ymm0,-0x11(%0,%1,8)" : : "r"(base), "r"(index));
}
static void base1x8(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rax") = ptr;
    asm ("testb $0x0,-0x1(%0)" : : "r"(base));
}
static void base1x16(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rbx") = ptr;
    asm ("testw $0x0,-0x1(%0)" : : "r"(base));
}
static void base1x32(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rcx") = ptr;
    asm ("testl $0x0,-0x1(%0)" : : "r"(base));
}
static void base1x64(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdx") = ptr;
    asm ("testq $0x0,-0x1(%0)" : : "r"(base));
}
static void index1x8(intptr_t ptr, ssize_t offset)
{
    register intptr_t index asm("rax") = offset;
    asm ("testb $0x0,0x123456(,%0,1)" : : "r"(index));
}
static void index1x16(intptr_t ptr, ssize_t offset)
{
    register intptr_t index asm("rbx") = offset;
    asm ("testw $0x0,0x123456(,%0,1)" : : "r"(index));
}
static void index1x32(intptr_t ptr, ssize_t offset)
{
    register intptr_t index asm("rcx") = offset;
    asm ("testl $0x0,0x123456(,%0,1)" : : "r"(index));
}
static void index1x64(intptr_t ptr, ssize_t offset)
{
    register intptr_t index asm("rdx") = offset;
    asm ("testq $0x0,0x123456(,%0,1)" : : "r"(index));
}
static void funky1x8(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rsi") = ptr;
    asm ("testb $0x0,-0xabcdef(%0,%0,8)" : : "r"(base));
}
static void funky1x16(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rdi") = ptr;
    asm ("testw $0x0,-0xabcdef(%0,%0,8)" : : "r"(base));
}
static void funky1x32(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("rbp") = ptr;
    asm ("testl $0x0,-0xabcdef(%0,%0,8)" : : "r"(base));
}
static void funky1x64(intptr_t ptr, ssize_t offset)
{
    register intptr_t base asm("r15") = ptr;
    asm ("testq $0x0,-0xabcdef(%0,%0,8)" : : "r"(base));
}
static void memset8x8(intptr_t ptr, ssize_t offset)
{
    memset((void *)(ptr + offset), 0, unknown(8 * sizeof(uint8_t)));
}
static void memcpy8x8(intptr_t ptr, ssize_t offset)
{
    const char mem[8] = "ABCDEFG";
    memcpy((void *)(ptr + offset), mem, unknown(sizeof(mem)));
}
static void memcpy8x8f(intptr_t ptr, ssize_t offset)
{
    char mem[8];
    memcpy(mem, (void *)(ptr + offset), unknown(sizeof(mem)));
}
static void memcmp8x8(intptr_t ptr, ssize_t offset)
{
    const char mem[8] = {'\0'};
    use(memcmp(mem, (void *)(ptr + offset), unknown(sizeof(mem))));
}
static void strcpy8x8(intptr_t ptr, ssize_t offset)
{
    const char str[8] = "ABCDEFG";
    strcpy((void *)(ptr + offset), str);
}
static void strcat8x8(intptr_t ptr, ssize_t offset)
{
    const char str[8] = "ABCDEFG";
    strcat((void *)(ptr + offset), str);
}
static void double_free(intptr_t ptr, ssize_t offset)
{
    free((void *)ptr);
}

/*
 * Tests.
 */
static const struct test_s tests[] =
{
    {-32, 32, "r[1x8,f,1]",    read1x8f,    0x0,  1, sizeof(uint8_t)},
    {-32, 32, "r[1x16,f,1]",   read1x16f,   0x0,  1, sizeof(uint16_t)},
    {-32, 32, "r[1x32,f,1]",   read1x32f,   0x0,  1, sizeof(uint32_t)},
    {-32, 32, "r[1x64,f,1]",   read1x64f,   0x0,  1, sizeof(uint64_t)},
    {-32, 32, "r[4x32,f,1]",   read4x32f,   0x0,  1, 4 * sizeof(uint32_t)},
    {-32, 32, "r[1x8,c,1]",    read1x8c,    0x0,  1, sizeof(uint8_t)},
    {-32, 32, "r[1x16,c,1]",   read1x16c,   0x0,  1, sizeof(uint16_t)},
    {-32, 32, "r[1x32,c,1]",   read1x32c,   0x0,  1, sizeof(uint32_t)},
    {-32, 32, "r[1x64,c,1]",   read1x64c,   0x0,  1, sizeof(uint64_t)},
    {-32, 32, "r[4x32,c,1]",   read4x32c,   0x0,  1, 4 * sizeof(uint32_t)},
    {-32, 32, "w[1x8,f,1]",    write1x8f,   0x0,  1, sizeof(uint8_t)},
    {-32, 32, "w[1x16,f,1]",   write1x16f,  0x0,  1, sizeof(uint16_t)},
    {-32, 32, "w[1x32,f,1]",   write1x32f,  0x0,  1, sizeof(uint32_t)},
    {-32, 32, "w[1x64,f,1]",   write1x64f,  0x0,  1, sizeof(uint64_t)},
    {-32, 32, "w[4x32,f,1]",   write4x32f,  0x0,  1, 4 * sizeof(uint32_t)},
    {-32, 32, "w[1x8,c,1]",    write1x8c,   0x0,  1, sizeof(uint8_t)},
    {-32, 32, "w[1x16,c,1]",   write1x16c,  0x0,  1, sizeof(uint16_t)},
    {-32, 32, "w[1x32,c,1]",   write1x32c,  0x0,  1, sizeof(uint32_t)},
    {-32, 32, "w[1x64,c,1]",   write1x64c,  0x0,  1, sizeof(uint64_t)},
    {-32, 32, "w[4x32,f,1]",   write4x32c,  0x0,  1, 4 * sizeof(uint32_t)},
    {-32, 32, "r[1x8,f,2]",    read1x8f2,   0x10, 2, sizeof(uint8_t)},
    {-32, 32, "r[1x16,f,2]",   read1x16f2,  0x10, 2, sizeof(uint16_t)},
    {-32, 32, "r[1x32,f,2]",   read1x32f2,  0x10, 2, sizeof(uint32_t)},
    {-32, 32, "r[1x64,f,2]",   read1x64f2,  0x10, 2, sizeof(uint64_t)},
    {-32, 32, "r[1x8,c,2]",    read1x8c2,   0x10, 2, sizeof(uint8_t)},
    {-32, 32, "r[1x16,c,2]",   read1x16c2,  0x10, 2, sizeof(uint16_t)},
    {-32, 32, "r[1x32,c,2]",   read1x32c2,  0x10, 2, sizeof(uint32_t)},
    {-32, 32, "r[1x64,c,2]",   read1x64c2,  0x10, 2, sizeof(uint64_t)},
    {-32, 32, "w[1x8,f,2]",    write1x8f2,  0x10, 2, sizeof(uint8_t)},
    {-32, 32, "w[1x16,f,2]",   write1x16f2, 0x10, 2, sizeof(uint16_t)},
    {-32, 32, "w[1x32,f,2]",   write1x32f2, 0x10, 2, sizeof(uint32_t)},
    {-32, 32, "w[1x64,f,2]",   write1x64f2, 0x10, 2, sizeof(uint64_t)},
    {-32, 32, "w[1x8,c,2]",    write1x8c2,  0x10, 2, sizeof(uint8_t)},
    {-32, 32, "w[1x16,c,2]",   write1x16c2, 0x10, 2, sizeof(uint16_t)},
    {-32, 32, "w[1x32,c,2]",   write1x32c2, 0x10, 2, sizeof(uint32_t)},
    {-32, 32, "w[1x64,c,2]",   write1x64c2, 0x10, 2, sizeof(uint64_t)},
    {-31, 32, "r[1x16,f,2]~",  read1x16f2,  0x10, 2, sizeof(uint16_t)},
    {-29, 32, "r[1x32,f,2]~",  read1x32f2,  0x10, 2, sizeof(uint32_t)},
    {-27, 32, "r[1x64,f,2]~",  read1x64f2,  0x10, 2, sizeof(uint64_t)},
    {-32, 32, "sse[1x128]",    sse1x128,   -0x10, 4, 2 * sizeof(uint64_t)},
    {-32, 32, "avx[1x256]",    avx1x256,   -0x11, 8, 4 * sizeof(uint64_t)},
    {0,   0,  "base[1x8]",     base1x8,    -0x1, 0, sizeof(uint8_t)},
    {0,   0,  "base[1x16]",    base1x16,   -0x1, 0, sizeof(uint16_t)},
    {0,   0,  "base[1x32]",    base1x32,   -0x1, 0, sizeof(uint32_t)},
    {0,   0,  "base[1x64]",    base1x64,   -0x1, 0, sizeof(uint64_t)},
    {-16, 16, "index[1x8]",    index1x8,    0x123456, 1, sizeof(uint8_t)},
    {-16, 16, "index[1x16]",   index1x16,   0x123456, 1, sizeof(uint16_t)},
    {-16, 16, "index[1x32]",   index1x32,   0x123456, 1, sizeof(uint32_t)},
    {-16, 16, "index[1x64]",   index1x64,   0x123456, 1, sizeof(uint64_t)},
    {0,   0,  "funky[1x8]",    funky1x8,   -0xabcdef, 8, sizeof(uint8_t)},
    {0,   0,  "funky[1x16]",   funky1x16,  -0xabcdef, 8, sizeof(uint16_t)},
    {0,   0,  "funky[1x32]",   funky1x32,  -0xabcdef, 8, sizeof(uint32_t)},
    {0,   0,  "funky[1x64]",   funky1x64,  -0xabcdef, 8, sizeof(uint64_t)},
    {-16, 16, "memset[8x8]",   memset8x8,   0x0,  1, 8 * sizeof(uint8_t)},
    {-16, 16, "memcpy[8x8,t]", memcpy8x8,   0x0,  1, 8 * sizeof(uint8_t)},
    {-16, 16, "memcpy[8x8,f]", memcpy8x8f,  0x0,  1, 8 * sizeof(uint8_t)},
    {-16, 16, "memcmp[8x8]",   memcmp8x8,   0x0,  1, 8 * sizeof(uint8_t)},
    {-16, 16, "strcpy[8x8]",   strcpy8x8,   0x0,  1, 8 * sizeof(uint8_t)},
    {-16, 16, "strcat[8x8]",   strcat8x8,   0x0,  1, 8 * sizeof(uint8_t)},
    // UAF must come last:
    {-32, 32, "uaf[1x8]",      read1x8f,    0x0,  1, sizeof(uint8_t)},
    {-32, 32, "uaf[1x16]",     read1x16f,   0x0,  1, sizeof(uint16_t)},
    {-32, 32, "uaf[1x32]",     read1x32f,   0x0,  1, sizeof(uint32_t)},
    {-32, 32, "uaf[1x64]",     read1x64f,   0x0,  1, sizeof(uint64_t)},
    {0,   0,  "double_free",   double_free, 0xfffff, 1, sizeof(uint8_t)}, 
    {0, 0, NULL, NULL, 0x0, 0x0, 0x0}
};

/*
 * Run a test.  The test is run in a fork'ed process to simplify cleanup
 * and/or corrupt state.
 */
static bool run_test(const struct test_s *test, intptr_t lb, intptr_t ub,
    intptr_t ptr, ssize_t offset, size_t size)
{
#ifdef NO_FORK
    test->func(ptr, offset);
    return true;
#else
    bool error = false;
    pid_t pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "fork() failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        close(STDERR_FILENO);
        test->func(ptr, offset);
        _exit(EXIT_SUCCESS);
    }
    else
    {
        int status;
        if (waitpid(pid, &status, 0) < 0)
        {
            fprintf(stderr, "waitpid() failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT)
            error = true;
    }
    return (error == OOB(test, lb, ub, ptr, offset));
#endif
}

/*
 * RedFat testsuite.
 */
int main(void)
{
    ssize_t counter = 0;
    for (size_t size = 1; size <= 512; size++)
    {
        intptr_t ptr = (intptr_t)malloc(size);
        intptr_t lb  = ptr;
        intptr_t ub  = lb + size;
        memset((void *)ptr, 0x0, size);
        bool alloced = true;

        for (size_t i = 0; tests[i].name != NULL; i++)
        {
            bool index = (strncmp(tests[i].name, "index", 5) == 0);
            bool funky = (strncmp(tests[i].name, "funky", 5) == 0);
            bool uaf = (strncmp(tests[i].name, "uaf", 3) == 0);
            if (alloced && uaf)
            {
                free((void *)ptr);
                lb = ub = ptr;
                alloced = false;
            }
            for (size_t j = 0; j <= size; j++)
            {
                uintptr_t p = ptr + j;
                intptr_t old_lb_access = INTPTR_MIN;
                ssize_t offset_lo = tests[i].lo;
                ssize_t offset_hi = (ssize_t)size + tests[i].hi;
                if (index || funky)
                {
                    offset_lo += p - tests[i].disp;
                    offset_hi += p - tests[i].disp;
                    if (index)
                        p = 0x0;
                }
                for (ssize_t offset = offset_lo; offset < offset_hi; offset++)
                {
                    intptr_t lb_access = LB(&tests[i], p, offset);
                    intptr_t ub_access = UB(&tests[i], p, offset);
                    if (lb_access == old_lb_access)
                        break;
                    counter++;
                    old_lb_access = lb_access;
                    bool error = OOB(&tests[i], lb, ub, p, offset);
                    bool pass  = run_test(&tests[i], lb, ub, p, offset, size);
                    fprintf(stderr, "%.10zu:%zu:+%zu:%+zd:%s: %s%ld..%ld in "
                            "0..%ld%s: %s",
                        counter, size, j, offset, tests[i].name,
                        (error? "\33[33m": ""),
                        lb_access - lb, ub_access - lb, size,
                        (error? "\33[0m": ""),
                        (pass? "\33[32mPASS\33[0m\n": "\33[31mFAIL\33[0m "));
                    if (!pass)
                    {
                        fprintf(stderr, "[expected=%s, got=%s]\n",
                            (error? "error": "no-error"),
                            (error? "no-error": "error"));
                        exit(EXIT_FAILURE);
                    }
                }
                if (index) break;
            }
        }
    }
 
    return 0;
}

