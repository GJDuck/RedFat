# RedFat -- Binary Hardening System

RedFat is a tool for automatically hardening Linux `x86_64` ELF binary
executables against memory errors, including *buffer overflows* and
*use-after-free* errors.

RedFat is based on an amalgamation of two complementary memory error
detection technologies:

* *Poisoned Redzones*
* *Low-Fat-Pointers*

Using low-fat-pointers with binary code has some caveats, as is discussed
below.

## Releases

Binary releases of RedFat are available here:

* [https://github.com/GJDuck/RedFat/releases](https://github.com/GJDuck/RedFat/releases)

## Building

To build RedFat, simply run the script:

        $ ./build.sh

## Basic Usage

To use RedFat. simply run `redfat` with the name of a binary executable,
e.g.:

        $ ./redfat xterm

This will generate a hardened `xterm.redfat` binary.
To run the binary, the `libredfat.so` runtime system must be `LD_PRELOAD`'ed
as follows:

        $ LD_PRELOAD=$PWD/libredfat.so ./xterm.redfat

## Advanced Usage

The basic usage may suffer from *false detections* with some binaries.
This occurs when program (or compiler) deliberately creates out-of-bounds
(OOB) pointers, and accessing such OOB pointers is indistinguishable from
"real" memory errors under the basic low-fat-pointer checking.

To mitigate false detections, we can use *dynamic analysis* to determine
which memory access operations are likely to cause false detections.

First, we build an *allow-list-generation* version of the binary:

        $ ./redfat -Xallowlist-gen xterm

This will generate an `xterm.gen` file that can be used to generate an
*allow-list*.
To use, run the `gen` version of the binary on a suitable test suite,
ideally to maximize coverage:

        $ LD_PRELOAD=$PWD/libredfat.so ./xterm.gen

This process will generate an `xterm.allow` file which contains
information about each memory access.

Next, we run `redfat` using the allow-list:

        $ ./redfat -Xallowlist-use xterm

This will generate a hardened `xterm.redfat` binary.
This version uses a more conservative instrumentation for memory access
operations that are likely to be false detections.

## Options

The `redfat` tool supports several options to control the instrumentation
and optimization levels.

The main *instrumentation* options are:

* `-Xlowfat` (`-Xlowfat=false`):
  Enables (disables) low fat pointer instrumentation.
  If disabled, the tool will use redzone-only checking.
  Default: *enabled*.
* `-Xreads` (`-Xreads=false`):
  Enables (disables) memory read instrumentation.
  If disabled, the tool will only instrument memory writes.
  Note that (1) read instrumentation is expensive, and
  (2) many exploits (e.g., *control-flow-hijacking*) require a memory write
  operation.
  For this reason, memory reads are not instrumented by default.
  Default: *disabled*.
* `-Xsize` (`-Xsize=false`):
  Enables (disables) size metadata protection.
  RedFat stores object size metadata which itself may be vulnerable to attack.
  With size metadata protection, the size metadata is compared against the
  (immutable) low fat size metadata, which is sufficient to prevent overflows
  into adjacent objects.
  Default: *enabled*.
* `-Xdebug` (`-Xdebug=false`):
  Enables "debugging" mode that prints detailed information about any memory
  error that is detected.
  See *Debugging Mode* below for more information.
  Default: *disabled*.
* `-Xadjust` (`-Xadjust=false`):
  This experimental mode considers any pointer arithmetic from context
  instructions in the same basic-block.
  For example, if:

        add $0x8,%rdi
        mov $0x0,(%rdi,%rsi,8)

  Then the base pointer for the low-fat check will be `%rdi-0x8` rather than
  just `%rdi` (the default).
  This can improve the accuracy of low-fat checking.
  However, this mode also assumes the correctness of the basic-block recovery
  algorithm, so is not enabled by default.
  This mode is also not currently compatible with `-Xdebug` or `-Xallowlist`.

The main *optimization* options are:

* `-Oglobals` (`-Oglobals=false`):
  Enables (disables) the elimination of global object memory access
  instrumentation that cannot reach the heap.
  Default: *enabled*.
* `-Ostack` (`-Ostack=false`):
  Enables (disables) the elimination of stack object memory access
  instrumentation that cannot reach the heap.
  This optimization assumes that the stack pointer `%rsp` value is in the
  default relocation which is far from the heap.
  This is generally true for most programs, but the assumption could be
  violated by programs that allocate and use custom stacks on the heap
  (e.g., `malloc()`+`sigaltstack()`).
  Default: *enabled*.
* `-Obatch=N`:
  Group the instrumentation into batches of length `N` checks, where possible.
  This instrumentation depends on a static jump target recovery analysis.
  If the analysis is imperfect, this may result in missed instrumentation.
  However, the analysis should be accurate for most binaries.
  Default: 50.
* `-Omerge` (`-Omerge=false`):
  In a given batch, attempt to merge checks where possible.
  Default: *enabled*.

The main *allow-list* options are:

* `-Xallowlist-mode=MODE`:
  Set the allow-list instrumentation *mode* for advanced instrumentation
  control.
  Here, the `MODE` is represented by a 4-character string.
  The character *index* 0..3 determines how each allow-list entry
  (created by *allow-list generation*) should be instrumented.
  The possible index values are:

  - `0`: Lowfat-unsafe (false detection observed)
  - `1`: Lowfat-safe (no false detection observed)
  - `2`: Only non-heap pointers observed
  - `3`: Not reached

  The corresponding `MODE[index]` character determines the instrumentation:

  - `L`: Redzone+Lowfat instrumentation
  - `R`: Redzone-only instrumentation
  - `-`: No instrumentation

  Reasonable values for `MODE` are:

  - `"RLRR"`: Use Redzone+Lowfat instrumentation only for
    (observed) lowfat-safe memory access.
    This is the default `MODE`.
  - `"RL-R"`: Do not bother instrumenting memory access that was only
    (observed) using non-heap pointers.
    This can improve the performance of the instrumented binary,
    but at the risk of missing some memory errors on unexplored paths.
  - `"RLLL"`: Use Redzone+Lowfat instrumentation on all memory access
    that was not (observed to be) Lowfat-unsafe.
    This eliminates the observed false detections, but retains the risk of
    false detections on unexplored paths.

The LowFat runtime also supports options that can be enabled using
environment variables:

* `REDFAT_PROFILE=1`: Enable profiling information such as the number of
  allocations and total library checks.
  Default: *disabled*.
* `REDFAT_TEST=N`: Enable "test"-mode that randomly (once per `N`
  allocations) underallocates by a single byte.
  If instrumented code accesses the missing byte then a memory error should
  be detected.
  A zero value disables test-mode.
  Default: 0 (*disabled*).
* `REDFAT_QUARANTINE=N`: Delay re-allocation of objects until `N` bytes have
  been free'ed.
  This can help detect reuse-after-free errors by not immediately
  reallocating objects, at the cost of increased memory overheads.
  However, this can increase memory overheads.
  Note that `N` is a per-*region* value for each allocation size-class, so
  the total overhead could be `N*M` where `M` is the number of regions
  (typically ~60).
  Default: 0.
* `REDFAT_ZERO=1`: Enable the zero'ing of objects during deallocation.
  Provides additional defense against *use-after-free* errors and a basic
  defense against *unititalized-read* errors.
  However, zero'ing adds additional performance overheads.
  Default: *disabled*.
* `REDFAT_CANARY=1`: Enables a randomized canary to be placed at the end of
  all allocated objects.
  The canary provides additional protection for out-of-bounds write errors
  that may go undetected in uninstrumented code.
  This consumes an additional 8 bytes per allocation.
  Note that a canary is always placed at the beginning of all allocated
  objects since this does not consume additional space.
  Default: *disabled*.
* `REDFAT_ASLR=1`: Enables *Address Space Layout Randomization* (ASLR) for
  heap allocations.
  Default: *enabled*.

## Debugging Mode

By default, RedFat can detect if a memory error occurs, but cannot report any
information about the memory error, such as the kind of error (overflow,
use-after-free), the accessed object, etc.
This is by design, since tracking this information would make the
instrumentation slower.

For more detailed information about memory errors, RedFat also supports a
"debugging" mode that can be enabled via the `-Xdebug` option:

       $ ./redfat -Xdebug xterm

Unlike the default mode, the debugging mode will print detailed information
about any memory error detected.
For example:

        REDFAT WARNING: out-of-bounds error detected!
                instruction = movb $0x0, -0x20(%rdx) [0x2d698]
                access.ptr  = 0x3073820560
                access.size = 1
                access.obj  = [-48..+16]
                base.ptr    = 0x3073820580 (+32)
                base.obj    = [+48..+144] (free)

Here:

* `instruction`: is the instruction and [address] where the memory error
  was detected.
* `access.ptr`: is the pointer that was accessed by the instruction.
* `access.size`: is the size of the access in bytes.
* `access.obj`: is the (free?) object that was accessed
  (relative to `access.ptr`).
* `base.ptr`: is the base pointer with (offset) relative to `access.ptr`.
* `base.obj`: is the (free?) object pointed to by the base pointer
  (relative to `access.ptr`).

In this example, the base and access pointers refer to different objects,
meaning that the access is deemed to be a out-of-bounds memory error.

Unlike the default mode:

* The program will *not* be terminated if a memory error is detected.
  However, at most one message will be printed for each instruction.
* There is no allow-list, so false positives will be reported just the same
  as real memory errors.
* Debugging mode is significantly slower than the default mode.

## Profiling Mode

RedFat supports a "profiling" mode that can be enabled via the `-P` option:

       $ ./redfat -P xterm

Profiling mode is similar to the default mode,
but the following information to the terminal on program exit:

* `total.time`: Total runtime (ms).
* `total.maxrss`: Max *resident set size* (kB).
* `redzone.checks`: Total redzone checks (before `-Omerge`).
* `redzone.checks (optimized)`: Total redzone checks (after `-Omerge`).
* `redzone.checks (heap)`: Total redzone checks (after `-Omerge`) on
   heap pointers.
* `lowfat.checks`: Total lowfat checks (before `-Omerge`).
* `lowfat.checks (optimized)`: Total lowfat checks (after `-Omerge`).
* `lowfat.checks (heap)`: Total lowfat checks (after `-Omerge`) on
   heap pointers.

By enabling the `REDFAT_PROFILE=1` environment variable, additional
information will be printed:

* `total.allocs`: Total heap allocations.
* `library.checks`: Total library function (e.g., `memset`, `memcpy`, etc.)
  checks.
* `library.checks (heap)`: Total library function checks on heap pointers.

Note that:

* RedFat can only detect memory errors on heap pointers `(heap)`.
* Profiling mode is somewhat slower than the default mode.
* Profiling information will *not* be printed if the instrumented binary
  exits abnormally (e.g., crash) or if the binary calls fast exit
  (e.g., `_Exit()`, etc.).

The ratio of heap versus non-heap pointers depends on the program, and how it
chooses to allocate and access memory.
If the ratio of `(heap)` is low, it may not be worthwhile to use RedFat on
the binary.

## Limitations

* RedFat inherits all the limitations of the underlying E9Tool/E9Patch
  tool chain.
  Fortunately, E9Patch should work for most binaries.
* RedFat can detect *object-bounds* (e.g., buffer overflow) and
  *(re)use-after-free* errors, but not
  *sub-object-bounds* nor *type-confusion* errors.
  The latter are difficult to detect at the binary-level which lacks type
  information.
* RedFat is based on *static binary rewriting*, which means that only the
  binary explicitly passed to RedFat will be instrumented, and *not* any
  dynamically linked library dependencies.
  It is possible to separately instrument library dependencies with
  RedFat, and use `LD_LIBRARY_PATH` to replace the default (uninstrumented)
  library.
* Low-fat-pointer checking is limited to unambigious pointer arithmetic.
  In practice, this means `x86_64` memory operands only.

## Troubleshooting

Generally, most binaries should work without an issue.
When a problem does occur, it is usually one of the following:

* **`error: binary "program" exports a custom "malloc" function`**:
  This occurs when an executable defines its own `malloc()` function and
  exports it.
  If this occurs, the `LD_PRELOAD` trick will not replace this custom malloc,
  meaning that the instrumented binary will not be protected.
  You can force instrumentation anyway (e.g., for performance testing) using
  the `-force` option:

        $ ./redfat -force xterm 

  For some binaries, it may be possible to manually remove the custom
  malloc (with some effort) using a separate binary rewriting (e.g., overwrite
  entries in the dynamic symbol table).
  However, this functionality is not currently provided by RedFat itself.
* **`warning: failed to disassemble byte 0xXX at address 0xYYYY in section ".text"`**:
  This warning occurs when data is detected in the code section(s).
  This can be fixed by manually excluding specific address ranges from
  disassembly using the E9Tool `-E` option, e.g.:

         $ ./redfat xterm -- -E ADDR1..ADDR2

  Here, `ADDR1..ADDR2` is the address range to exclude from disassembly.

  Note that E9Tool (and by extension, RedFat) only uses a basic (linear)
  disassembler by default.
  This works for most binaries, but not binaries that mix code and data.
  For the latter, some kind of manual disassembly (using `-E`) is
  recommended.
* **`warning: the number of virtual mappings (XXX) exceeds the default system limit (YYY)`**:
  This occurs when the instrumented binary uses too many mappings.
  This can be fixed by increasing the mapping size to a suitable new limit
  (`ZZZ > XXX`):

         $ sudo sysctl -w vm.max_map_count=ZZZ

  Alternatively, the issue can be fixed by decreasing the compression level
  (at the cost of larger instrumented binary file sizes) using the E9Tool
  `-c` option, e.g.:

         $ ./redfat xterm -- -c N

  where `N` is a number `0..9` (lower numbers mean less compression).
* **`e9patch loader error: mmap(addr=ADDR,size=SIZE,offset=+OFFSET,prot=PROT) failed (errno=12)`**:
  This error occurs when you attempt to run an instrumented binary that uses
  too many mappings.
  See above for the problem description and solution.
* **`REDFAT ERROR: the REDFAT runtime (libredfat.so) has not been LD_PRELOAD'ed`**:
  As the error message explains, this error occurs when you attempt to run an
  instrumented binary without `LD_PRELOAD`'ing the `libredfat.so` binary.
  You can also define `REDFAT_DISABLE=1` to run the binary anyway (but
  with the instrumentation costs and no memory error protection).
* **`REDFAT ERROR: out-of-bounds/use-after-free error detected!`**:
  A memory error was detected.
  If the binary was **not** instrumented with `-Xallowlist-use`, then this
  could be a *false detection* (see the *Advanced Usage* above).
  Otherwise, this could be a genuine error and should be investigated.
* **`Illegal Instruction`**:
  This could be a memory error detected by RedFat.
  By default, RedFat will raise the `SIGILL` (Illegal Instruction) signal
  whenever a out-of-bounds/use-after-free error is detected.
  The signal is raised using the `x86_64` `ud2` instruction.
  Normally, the RedFat runtime system will catch the signal and print the
  `error detected` message shown above.
  However, if the program resets the signal handler, or installs a
  different signal handler, the error may be reported as an illegal
  instruction.
* **`Segmentation Fault`**:
  "Wildly" out-of-bounds errors may result in a `SIGSEGV` rather than a
  `SIGILL`.
  Alternatively, this could be some other issue, such as the binary breaking
  one of the assumptions of static rewriting (e.g., self-modifying code),
  or some other bug (please report it).

## License

This software has been released under the GNU Public License (GPL) Version 3.

Some specific files are released under the MIT license (check the file
preamble).

## Authors

RedFat is written by Gregory J. Duck.
The initial prototyping and testing of RedFat was completed by Yuntong Zhang.

## Publication

* Gregory J. Duck, Yuntong Zhang, Roland H. C. Yap,
  [Hardening Binaries against More Memory Errors](https://www.comp.nus.edu.sg/~gregory/papers/redfat.pdf),
  European Conference on Computer Systems (EuroSys), 2022

## See Also

* [LibRedFat](https://github.com/GJDuck/libredfat): A hardened malloc * implementation.
* [E9Patch](https://github.com/GJDuck/e9patch): A scalable binary rewriting system.
* [LowFat](https://github.com/GJDuck/LowFat): Lean C/C++ bounds checking with low-fat pointers

## Bugs

RedFat is considered beta-quality software.
Please report bugs here:

* [https://github.com/GJDuck/RedFat/issues](https://github.com/GJDuck/RedFat/issues)

## Acknowledgements

This work was partially supported by the National Satellite of Excellence in
Trustworthy Software Systems, funded by the National Research Foundation (NRF)
Singapore under the National Cybersecurity R&D (NCR) programme.

This work was partially supported by the Ministry of Education, Singapore
(Grant No. MOE2018-T2-1-142).

