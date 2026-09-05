# What's actually inside Sober

Notes from reverse-engineering the Sober binaries, written up for anyone who has to
work around them (AppImage packaging, debugging the random crashes, or just
curiosity). Everything here was checked by hand — disassembly, live memory dumps and
re-runs on clean machines — and every number is from the build currently shipped in
the flatpak manifest (`sober-binaries-unified.tar.zst`, sha256
`b60ba8d894f9a0e99ef7042d72db1c87db80a6d3c8c92bd54dc88a12b752946b`). If a claim is
second-hand (someone else's observation from the issue thread) it says so.

Short version first: the `sober` executable is a decoy. The real program lives in
`libloader.so`, which takes over the process before the executable's own code ever
runs, decrypts an internal engine into anonymous memory, re-execs itself with a
scrubbed environment, and then ptraces its own child for the rest of its life. Every
crash we've been chasing in the issue thread is this machinery aborting on purpose,
and the "requires a CPU with x86-64-v2 features" message is a mask it puts on while
doing so.

## The five files

`sober` is 7,615,515 bytes, `libloader.so` 4,261,489, `libbadcpu.so` 390,104,
`libmimalloc.so` 224,392, and `sober_services` 1,132,200. All of them ship with the
section headers stripped from the ELF, so normal tooling (objdump, nm, anything that
wants sections) gives up immediately. The dynamic symbol tables are still there, which
is enough to reconstruct the rest if you write your own program-header-based loader —
that's what the scripts in this repo do.

`sober_services` is the odd one out: a plain WebKitGTK6 login window with no protection
worth mentioning. `libmimalloc.so` looks close to an upstream build. All the
interesting behaviour is in `libloader.so` and `libbadcpu.so`, and in the `sober`
binary in a strange way I'll get to.

Both loader libraries also link `ld-linux-x86-64.so.2` as if it were an ordinary
shared library (`DT_NEEDED`), which is unusual and worth remembering when you're
staring at `ldd` output wondering why the dynamic loader is listed twice.

## The executable that never runs

The `sober` file has one RX load segment: file offset 0x1e5400, mapped at 0x1e6400,
0x537f30 bytes (5,472,048 bytes, about 5.5 MB of code). Sliding a 4 KiB entropy window
across it, every single window measures above 7.2 bits per byte — the whole segment is
ciphertext. The dynamic tags point into it too: `DT_INIT` is 0x716074 and all 47
`INIT_ARRAY` entries sit inside that region.

You'd expect *something* to decrypt it before those get called. Nothing does, because
nothing ever calls them. Running with `LD_DEBUG=files` (this works, because the
scrubbing I describe below happens later) you can watch the loader initialise every
dependency — libc, the GL stack, gstreamer, libbadcpu, libloader — then see
`libseccomp.so.2` get dlopen'd by libloader, and then the log just stops. There is no
`calling init: ./sober` and no `transferring control` line. ld.so never hands control
to the executable at all. A core dump taken at crash time shows the RX segment as
clean, never-written file pages, and reading the live mapping through
`/proc/pid/mem` a third of a second into the run shows ciphertext sitting there
untouched.

So the encrypted-looking code segment is a scarecrow. It holds the dynamic-linking
necessities and 5.5 MB of noise. The actual program is elsewhere.

## How libloader takes over

`libloader.so` has five constructors. The interesting one is the last, at 0xf1d40,
which jumps into the engine bootstrap at 0xd2960. That function does several things
worth describing.

It dlopens `libseccomp.so.2` with `RTLD_NOW|RTLD_GLOBAL` (call site 0x1e022). It
makes a couple of `write()` calls with fd -1, which can't succeed and look like
deliberate noise to confuse anyone tracing calls. And then it enters a proper
control-flow-flattened state machine — a dispatcher at 0xd2a10 comparing a state
register against long chains of immediates, each state doing one small operation on a
running 64-bit value (xor, add, bswap, shld) before hopping to the next. Following it
by hand, it derives key material, including the constant 0xc9af6eac4605b1f6, from a
start value of zero. This is compiler-pass obfuscation, the same family of tricks as
OLLVM's flattening, applied to the key schedule so you can't just read the key off
the stack.

Later in the same area, the code copies 1,750,472 bytes (0x1ab5c8) from rodata at
0x1804a8 into a fresh heap allocation. That blob measures 7.998 bits/byte of entropy —
maxed out, perfectly random-looking. This is the encrypted engine. Right after the
copy, the code walks scattered stack slots one byte at a time with `movzx`/`pinsrb`,
gathering them into XMM registers to build 16-byte keys. The decode helpers XOR
against 16-byte constants loaded from rodata (`pxor` at 0x19ad7, 0x19bca, 0x19c40,
0x19c99 and friends).

There's no AES-NI anywhere (no `aesenc`/`aesdec`/`aeskeygenassist` opcodes, no S-box
table), no SHA extensions, no ChaCha constant, but there is a dense cluster of
`pclmulqdq` instructions around 0x12d9bb–0x12db40 — carry-less multiplication, the
building block of GHASH-style authentication. So the cipher is custom, software-only,
with CLMUL checksums. I want to be honest about how far I got: I did not break it.
Repeating-key XOR known-plaintext attacks against strings we know must exist
(`.flatpak-info`, the error messages, and so on) all come up empty across periods 1 to
32, single-byte XOR/ADD/SUB likewise, because the keystream isn't periodic. Getting
the real keys means reversing the flattened derivation state by state.

## The re-exec and the environment scrub

After the bootstrap, the process re-executes itself through `/proc/self/exe`. You can
see this plainly in `/proc`: every generation of the launcher has
`Cmdline: /proc/self/exe`. The new environment is built by hand rather than inherited
— `LD_LIBRARY_PATH`, `LD_PRELOAD`, `LD_DEBUG` and friends are dropped.

This is why the AppImage's bundled libraries kept being ignored during early testing:
the first process honours `LD_LIBRARY_PATH`, but the child it re-execs into does not,
and only `$ORIGIN` runpaths survive. It also means `LD_PRELOAD` loggers only ever see
the first generation. Anything the child does has to be watched from outside, which
is what the `scrape.c` in this repo is for — it forks the target as its own child and
reads `/proc/pid/mem` and `/proc/pid/maps` directly, no ptrace involved.

## It ptraces itself, and it won't live without it

On a machine where the whole process tree is watched, the shape of the thing becomes
clear. There are two launcher processes. The parent, untraced. The child, forked from
it, sitting in tracing stop:

```
Name: sober   Pid: 2906  PPid: 2905  Cmdline: /proc/self/exe  TracerPid: 0
Name: sober   Pid: 2907  PPid: 2906  Cmdline: /proc/self/exe  TracerPid: 2906  State: t (tracing stop)
```

The parent debugs its own child, full time. This is the answer to the oldest mystery
in the issue thread: `strace ./sober` can't ever work, because the process needs to
occupy its own tracer slot, and gdb has the same problem. It also explains the
behaviour on locked-down systems. In the sandbox where I did most of the static work,
ptrace is blocked outright by seccomp, and Sober responds with the only plain-spoken
error message in the whole binary:

```
Failed to initialize core functionality. Your system security policy may be preventing Sober from starting.
Consult your operating system's documentation to enable ptrace (usually via the `kernel.yama.ptrace_scope` sysctl).
```

...printed twice, then exit code 139. So on any distribution that blocks ptrace or
restricts it hard, Sober is dead by design, before it ever looks at flatpak
anything.

What the ptrace link is *for* is most likely the memory protection itself —
decrypt-on-fault and re-encrypt-behind, with the parent handling the child's stops.
The child really does sit in `tracing stop` across consecutive snapshots. I can't
prove the page-granular protocol without being able to attach a debugger, which is
exactly the point of the design.

## Where decrypted code actually runs

Scraping the child's mappings on a runner, two places hold real, executing code that
exists nowhere on disk.

One is an anonymous `r-xp` mapping of exactly 0x85000 bytes, allocated right next to
the dlopen'd libseccomp. Same size, same neighbourhood, on every run and every
machine I tried. The strings inside it are nearly nonexistent — CPUID vendor
fragments, `processo`/`vendor_i`/`cpu fami` from a cpuid crate, a `[vsyscall]`
mention. This is the engine proper.

The other is the mimalloc heap arena — a 1 GiB `[anon:mimalloc]` mapping — where
decrypted Rust functions live while in use. Scraped rounds contain hundreds of
`0f 0b bf` sequences (`ud2` followed by `mov edi, N`), which is just what Rust
codegen looks like when it's sitting in memory.

And the engine re-encrypts behind itself. Comparing live memory against the files on
disk at the same moment: libbadcpu's own text differs from its file (scrambled again
after use), an untouched system library like libgstbase is byte-identical to disk,
and I caught libcares — a system library, not Sober's — mid-sweep, with a plain
counter ramp (80 81 82 83 …) across a page that had been all zeros. That ramp is a
keystream over a zero page: the re-encryptor walking everything the process ever
touched. The core dump being full of *clean* file-backed pages for regions that
clearly executed fits the same trick — drop the modified pages (madvise or remap) and
the file's ciphertext comes back, leaving nothing to dump.

## libbadcpu: the emulator that mostly prints lies

libbadcpu's constructor at 0x197a0 does a CPUID check and installs a SIGILL handler,
and the handler install is unconditional — only the warning text is gated on CPU
features. The handler at 0x17560 is a genuine, fairly complete SSE4.2
trap-and-emulate decoder: prefix parsing, 0f 38 escape handling, jump tables, the
lot. That part is real and does what it says — it exists to run Roblox on CPUs below
x86-64-v2.

But `ud2` is not an SSE instruction. When the engine decides a check has failed, it
writes a `ud2` into its own decrypted code and lets execution run into it, and the
handler — unable to emulate it — prints the box we've all been staring at:

```
FATAL: Unrecognized Instruction
Received signal: 4 (Illegal Instruction)
Instruction Bytes: [f, b, bf, 1, 0, 0, 0, be]
This program requires a CPU with x86-64-v2 features.
```

The bytes after the `ud2` — `bf 01 00 00 00 be` — are just the next instructions in
the stream (`mov edi, 1; mov esi, …`). They're not part of any "faulting
instruction"; the FATAL printer just grabs eight bytes at RIP. The tail of the
message even admits the truth: "illegal instruction errors can also be thrown due to
the program encountering something it didn't expect as a way to quickly stop
itself". That sentence is the accurate description of every one of these crashes.
Samueru watched the emulator write `ud2 + bf … be` into memory at runtime in the
AppImage runs and that matches exactly what the machinery here is built to do.

## The crash, reproduced properly

On a GitHub runner (AMD EPYC 7763, so no missing CPU features), bare `: | ./sober`
produces the same FATAL box, same bytes, RIP always ending in `…7dae`, every time.
I ran it five ways to find out which check it was failing:

1. bare, nothing special
2. with an LD_PRELOAD call logger
3. placed in `/app/bin`
4. with `/.flatpak-info` written in real flatpak format, `FLATPAK_ID` exported, and
   flatpak 1.14.6 actually installed
5. all of the above plus an Xvfb display and a session dbus

Same crash, same offset, all five. So the abort is not about the flatpak version, not
about `/.flatpak-info` existing, not the `/app/bin` path, not the display, not the
bus. The abort site sits at a fixed offset 0x7dae in its mapping, which by size and
placement is the decrypted engine module (I'll be honest that I matched it by
consistency across runs rather than catching the exact byte at crash time). What
bwrap provides that a plain shell doesn't — a mount namespace with a controlled
mountinfo, a proc namespace — is the obvious next suspect, and the fact that it dies
*silently* here, printing nothing at all before the FATAL box, is itself a choice:
outside the GUI flow, failed checks don't explain themselves.

For the record, the crash people saw inside games after Roblox loaded may still be a
different animal (Luau codegen was floated upstream and I can't rule it in or out —
this build never got that far). But the launcher crash family — startup, login
screen, mouse-wiggling-for-minutes — is this abort, and it isn't glibc, isn't the
GPU driver, isn't libcurl, and definitely isn't the CPU.

## String obfuscation

None of the interesting strings exist as strings. They're assembled on the stack from
`movabs` immediates and decoded inline with per-string keystreams. Short ones are
split up the same way the compiler would do it anyway (`/proc/se` + `lf/maps`
written as two separate moves), so you can't even grep for the pieces. The known
error messages, path names, everything the checks touch — all built this way. The
only way to inventory them is to catch them decoded in memory, which is what the
scrape rounds do; roughly 3,800 unique strings came out of the runs, including the
seccomp version probe, a full kernel-version parser's error set for
`/proc/sys/kernel/osrelease`, `gnu_get_libc_version`, and the goblin ELF parser's
internal error strings. The build compiler leaked too: rustc 1.98.0-nightly
(54333ff07, 2026-05-22).

## Integrity checking

libbadcpu and libloader import `realpath`, `readlink`, `dl_iterate_phdr`, `statx` and
`fstat64`, and the runtime strings include goblin's whole ELF-parsing error set and
`/proc/self/maps` handling. So the engine walks its own loaded objects, parses them,
and checksums them — the CLMUL cluster is almost certainly that. This is why the
one-patched-byte experiment from the issue thread (patch a byte, binary refuses to
start, empty log) behaves the way it does: patched ciphertext decrypts to garbage,
the checksum catches it, and the engine aborts without a word. There is no patchable
check to NOP out. That whole avenue is closed unless the cipher falls first.

## Is any of this malware?

In the sense people mean: no. Hashes of all shipped files are unchanged after every
run, so it doesn't rewrite itself on disk. No persistence, no units, no autostart.
It spawns exactly two kinds of process in every run I captured: further generations
of `/proc/self/exe`, and `sober_services` for the login window. Network use in the
phases reached was its own endpoints. It reads `/proc/self/*`,
`/proc/sys/kernel/osrelease`, `/dev/urandom`, the usual XDG directories, and CPUID.
The seccomp library gets loaded at constructor time, but the launcher processes
themselves still showed `Seccomp: 0` in `/proc/status` at capture time — the filter
presumably lands on the Roblox child later, which these runs never reached.

What it *is* is hostile to analysis, deliberately and skillfully. Decoy executable,
constructor hijack, environment scrub, self-ptrace, runtime encryption with
re-encryption behind execution, silent aborts, a fake CPU-error message on the way
out. Commercial protector work, not malware.

## What this means for the AppImage

bwrap stays the right answer for now. It satisfies the path and file checks by
namespace, it preserves the self-ptrace (a plain userns keeps ptrace of your own
children working), and it apparently satisfies whatever mount-view check kills the
bare runs. A leaner fake-flatpak namespace — bind the `.flatpak-info`, bind the
AppDir at `/app/bin`, pass the display and bus through — might work and would drop
the full bwrap dependency, but only after the remaining check is identified, and
that means either a live bwrap-vs-bare mountinfo diff experiment or someone putting
real weeks into the cipher and the ptrace protocol. Patching is a dead end, as
established above.

## Reproducing any of this

The tooling is in this repo. `elfkit.py` and `descent.py` rebuild function maps from
the sectionless ELFs. `spy.c` and `spy2.c` are the LD_PRELOAD loggers (first
generation only). `scrape.c` is the one that matters: it runs the target as a child
and periodically walks the whole process tree's `/proc` entries — status (which is
where the `TracerPid` lines come from), maps, and memory of every writable or
executable region — no ptrace, so Sober doesn't notice. The observation workflow
glues it together on a runner, since ptrace has to work there for Sober to get past
its own first check.
