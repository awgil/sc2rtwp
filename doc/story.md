# Starcraft 2 Real-time-with-pause

## Intro

I got the urge to play some SC2. However, I really suck at the kind of fast decision making that the game requires, and really miss the active pause feature, similar to what games like Homeworld / paradox GSGs provide.

SC2 design seems to be very hostile towards this idea, however. SC2 does offer different speed settings, but then the campaign locks the game to the highest setting anyway (unless you lower the difficulty, but then it's just boring).

Rather than trying to git gud, it's much more fun to hack the game instead, so let's do it!

Some quick googling painted a very sad picture - even though the game is still decently popular, there doesn't seem to be any dedicated reverse engineering community with documented prior knowledge.
I've only managed to find some dodgy places advertising various maphacks etc for *sale*. Not the sort of an open community I'd expect...

Firing up IDA and opening the exe, it quickly becomes apparent it's obfuscated - the import table is almost empty, the entry point is not looking good. Trying to attach a debugger to a running process shows some error.
Clearly, we're dealing with some anti-tampering measures. Although I did some reverse-engineering before, I never had to deal with that - so it's gonna be fun!

This document describes the measures I've encountered and how I've worked around them. It was written post-factum, so I might have forgotten some intermediate bits, but still maybe it will be helpful to anyone...

## First steps

Fully static analysis looks daunting, attaching a debugger doesn't work - so let's create a full dump instead and open it in IDA.
This works nicely, and immediately shows something resembling reasonable code.

Since we're trying to mess with timing, let's look for the callers of usual suspects like QueryPerformanceCounter, GetTickCount and so on. Exploring that, I quickly notice few things:
* There are too many callers, and I have no real way to guide myself in exploring the reference graph.
* A lot of the code was not properly marked as code during autoanalysis, so it's likely that I don't even see the full reference graph.
* Finally, some of the callers I've seen use QueryPerformanceCounter to calibrate rdtsc frequency, which implies that some other code uses rdtsc directly. Finding all instances of rdtsc instruction is hard, given the point above.

Still, it was not a complete failure - I've named some functions and globals that seem to have many refs, surely that will help me in the future when I stumble upon them when following other leads!

## Digging through strings

Next thing to try is IDA's standard strings view. It has a *lot* of entries - 11.5+ million! ctrl-c ctrl-v to a file and the file is half a gig!
Still, some keyword searches find me some useful leads - eg there are a bunch of strings like `GameSetGlobalTimeScale` and `GameGetSpeed` nearby.
Unfortunately, 'x' on them doesn't find anything useful - autoanalysis did miss tons of stuff apparently - so I made a very simple script to iterate over every byte in code segment of the main executable image, try decoding instruction starting at it, and checking whether any of the operands is a memory reference to one of the interesting strings.
This led me to two structures that seemed to contain speed-related fields and functions.

One example was a function with following properties:
* It checked some conditions, in one branch it would call some other short function and return 1, in the other it would do something with the string `Invalid time scale: ` and return 0. Looks like success & failure!
* The function was referenced from what is obviously a vtable, the error string was right next to it, and there were other vtables and strings around it, like `@Cheat/GodEnabled` - looks like we've found implementations of console commands!
* The vtable itself was referenced from a function that seemed to register all the console commands in some manager, and this one had a string `GlobalTimeScale` associated with it.
* Some googling showed that there's indeed a `GlobalTimeScale` debug command - so this tracks. Did some naming for console commands and vtables just in case.
* The function called on 'success' path (I've called it `setGlobalTimeScale`) is simple enough - it fetches some pointer and sets field 0xA0. Let's define a `TimingData` structure and name the dword at 0xA0 `globalTimeScale`.

The way `setGlobalTimeScale` fetches the pointer to its singleton is interesting:
```
SC2_x64_CODE:00007FF6AEB54280 000                 mov     eax, dword ptr cs:g_timingDataFuzzed
SC2_x64_CODE:00007FF6AEB54286 000                 xor     eax, cs:g_timingDataLoXor
SC2_x64_CODE:00007FF6AEB5428C 000                 mov     dword ptr [rsp+arg_8], eax
SC2_x64_CODE:00007FF6AEB54290 000                 mov     eax, dword ptr cs:g_timingDataFuzzed+4
SC2_x64_CODE:00007FF6AEB54296 000                 sub     eax, cs:g_timingDataHiSub
SC2_x64_CODE:00007FF6AEB5429C 000                 mov     dword ptr [rsp+arg_8+4], eax
SC2_x64_CODE:00007FF6AEB542A0 000                 mov     rax, [rsp+arg_8]
SC2_x64_CODE:00007FF6AEB542A5 000                 mov     [rax+TimingData.globalTimeScale], ecx
SC2_x64_CODE:00007FF6AEB542AB 000                 retn
```
Instead of storing it directly in some global, it obfuscates it somewhat (high dword has some constant added, low dword is xorred with some other constant). This pattern happens a lot in SC2 with various structures.
This obfuscation seems to be somewhat pointless really - I can 'x' either constant or a fuzzed pointer to see all refs, just as well as if it were not obfuscated - and it doesn't even hurt hexrays much (it's just a matter of manually doing 'y' to set the pointer type).
So I don't quite understand what is it supposed to achieve.

The other interesting function does a switch on an argument and returns 0x999 for 0, 0xCCC for 1, 0x1000 for 2, 0x1333 for 3 and 0x1666 for 4. This looks very similar to the game speed factors for 5 speed settings.
If 'normal' (setting 2) is 1.0 (corresponds to 0x1000), then 'slowest' is approximately 0.6 and 'fastest' is approximately 1.4 - exactly what one would expect to see.
This also suggests that SC2 uses fixed point values with 12 bits for fractional part - this is a good fact to know for interpreting future findings!
Let's call this function `getSpeedForSetting`.

## Modifying the code

Ok, actually, we have enough to try doing a simple hack - let's make `getSpeedForSetting` return some constant and see how game reacts.

The function signature is `int* getSpeedForSetting(int* out, int settingIndex)`, it returns `out`. This pattern looks like a 'large non-POD return value' - so the original code is likely to be something like `FixedPoint getSpeedForSetting(int index)`.
However, I'm not sure why doesn't it just return in normally in eax (since it's supposedly a small POD). In any case, this doesn't matter much now, let's just respect whatever signature we can see in IDA.

The simplest possible replacement is then something like:
```
mov rax, rcx
mov dword ptr [rcx], returned_value
ret
```
Let's hardcode both function start RVA (0x1557580 in my binary version) and the replacement code with the replacement constant for now.

To actually apply the patch, let's make a simple app that finds process by name (`SC2_x64.exe`, using `EnumProcesses` and `GetProcessImageFileNameA`), finds the imagebase (`EnumProcessModulesEx` and get back the first `HMODULE`), adds the RVA to find function address, and then calls `WriteProcessMemory` to apply the patch.
Of course, since the code is typically read/execute only, we also need to call `VirtualProtectEx` on the corresponding page to enable writes, and then restore original page protection after write just in case.

Surprisingly, `VirtualProtectEx` fails. The `GetLastError` result is not really helpful - however, some googling gives me ReactOS implementation of the `MiProtectVirtualMemory` that returns this error if the page is mapped with `SEC_NO_CHANGE` flag.
This flag is not documented in MSDN, but apparently it's a known anti-hooking technique - and it's quite easy to bypass by copying the entire section, unmapping old mapping, creating and mapping new one at the same address and copying contents back.

Since there's a period of time where effectively the entire code is gone, I need to suspend all running threads before doing that - and resume them again after all the patching is done. This also removes possibility of having game code call into something while we're mid patching, so it's a good idea to do regardless.
Note that 'suspending all threads in a process' is actually not a trivial thing:
* First of all, potentially new threads could be spawned between us enumerating all threads and actually suspending them. Luckily, SC2 doesn't seem to be spawning threads mid game, so I just ignore this potential race.
* Worse, any given thread could be suspended while it's doing something we're interfering with (eg executing preamble of a function that we're hooking). For this POC, I just ignore this too - worst case, game just crashes, and I can then restart it and try injection again.

Having done that, the patch now succeeds. It does not give the expected effect - the game still runs at usual speed - however, the mission timer (in the corner of minimap) now runs wildly, proving that we're not *wildly* off our target at least.
The game also crashes after few moments, but that's fine - we're very heavy handed now, no surprise if we're breaking some invariants and causing some consistency check to fail.

The first serious anti-tampering measure (undocumented `SEC_NO_CHANGE` flag) is now bypassed, that's a win!

## Injecting a DLL

Just manually writing *all* custom code via `WriteProcessMemory` is inconvenient, it would be much simpler to write a DLL with some normal C++ code and inject it instead.

The simplest imaginable way to inject a DLL is to get some code in the target process to run `LoadLibrary` with a string we provide it. And the simplest way to run the code is to `CreateRemoteThread` and have the thread function call `LoadLibrary`.
In fact, we don't even need to write *any* custom code - the `LoadLibrary` itself can be a threadproc, and then we just need to pass the string (path to the library) as the threadproc parameter!

So the solution is clear - let's allocate a block using `VirtualAllocEx`, write the library path to the beginning of it, and call `CreateRemoteThread`. The library itself can just apply the same patch we did before via `WriteProcessMemory` in its `DllMain`.
The address of the entry point can just be an address of the `LoadLibrary` of the calling process - for whatever reason, windows is guaranteed to load `kernel32.dll` at the same address in all processes across the system.
I did not know that originally, so I had some extra code that calculated the difference between `HMODULE`s of `kernel32` in both processes (which turned out to be always 0) and applied that to `LoadLibrary` address.
After calling `CreateRemoteThread` the injector process can just `WaitForSingleObject` to ensure the thread finishes before cleanup (freeing up memory allocated to contain the path and restoring protections - but most importantly resuming threads).

Surprisingly, this doesn't work - the remote thread finishes, but the effects I've expected (mission timer going wild) aren't happening. This one had me scratch my head for a while...

Ok, maybe `LoadLibrary` fails? Let's see why - for that, let's make the thread call `GetLastError` and set it as exitcode. This requires emitting some custom code for the entry point. So then, instead of using `LoadLibrary` as threadproc, let's use the start of the `VirtualAllocEx` block - and emit the following code there:
```
lea rcx, [rip + X]
call [rip + Y]
call [rip + Z]
ret
Y: dq address-of-LoadLibraryW
Z: dq address-of-GetLastError
X: path...
```

It expectedly fails, but the error code makes no sense - it doesn't look like what GetLastError could return at all! The high bits are set and all that...

Ok, let's try to run it under debugger - and instead of injecting into SC2 (which we can't attach debugger to, yet), write a custom simple test app and inject there.
Running both test app and injector under debugger, I can see injection working - the remote thread crashes attempting to access something beyond top of the stack. Of course - I forgot that x64 calling convention expects 4 qwords of shadow space allocated for first 4 arguments passed in registers - so let's do that, adding `sub rsp, 0x20` at the start and `add rsp, 0x20` at the end.
Running again, this crashes again on some unaligned access deep in windows code - of course, stack pointer is expected to be aligned to 0x10 - so we need to sub/add 0x28 instead.
With the final fix applied, injection into test app now works as expected.

Trying again with SC2 - I get the same result, no effect and weird exit code. This doesn't make sense...
Ok, maybe there is some weird anti-tampering thing that fucks over my injection process - let's use independent tool (ProcessHacker) to validate that there's a memory block allocated where `VirtualAllocEx` returned (there is), and that contents are what are expected (yes, there's a bunch of code, followed by library path string).
But then what's that? The first byte of code is 0xC3, that's weird, what's that? It's a `ret`! That's not what I tried to write!

Stepping through - I realize that right before `CreateRemoteThread`, the memory contents are what I expected, then after this call the first byte changes to 0xC3. Adding `CREATE_SUSPENDED` + `ResumeThread`, I notice that it changes after thread begins execution.
So - something that runs in the thread I've just created (all other threads are suspended) manages to replace the first instruction of the entrypoint with a ret, before it starts executing the entrypoint. It can't be some runtime library code (since I've just emitted the raw instructions for the entrypoint myself).
It has to be some OS level loader thing.

The only thing that comes to mind that can do that is some TLS support thing. Reading the PE spec on TLS, indeed there's a way to specify a list of callbacks to be executed on thread creation events.
Following the trail in IDA (`IMAGE_DOS_HEADER` at imagebase, `IMAGE_NT_HEADERS` at `e_lfanew`, `IMAGE_TLS_DIRECTORY` at where TLS directory entry says), I see that main exe module has three TLS callbacks defined.
The first callback function is weird - it has some weird conditional jumps to the middle of instructions and some really strange other instructions. Looks like some obfuscated code!

At this point, I haven't really bothered deciphering how it works (I did come back to it later, though!), and just patched the callback table entry to 0 before injection - and restored it after, just in case it's something important.
Trying injection again - and now it finally works, yay!

This one was probably the hardest measure to understand over this entire reverse-engineering effort (although I won't be surprised if it's a known technique, I just really lack experience with these things). Crafty bastards...

Anyway, now that injection works fine - let's try something else - like calling `setGlobalTimeScale`. It works (units start moving *reaaaaaly* slowly), although timers still run at the usual pace, which is not ok (eg it would not truly pause the game, triggers would be triggered at inappropriate time etc).
Calling the nearby function I've called `setSpeed` doesn't work at all. And the game still crashes after a while. But that's still good progress!

## Communication from injected DLL

To continue investigations, I'd like to hook a bunch of functions and see the stacks. I can't attach the debugger, but I don't really need to - I can just call `CaptureStackBackTrace` from my hook and print out the stack. I just need a way to display the information somehow.

The simplest way is to create another simple console app that creates a server end for a pipe, listens for messages and prints them out to console. The injected DLL can then just open the client end of the pipe and print messages there.

Then I can hook the `setSpeed` function, change the game speed from the UI, and inspect the stack. The interesting bit is another function that does the following:
* It reads some field from the input structure, then conditionally clamps it to some minimal value read from the same `TimingData` singleton (let's call the corresponding field `minimalSpeedIndex`).
* It calls some function that references `@UI/GameSpeedChanged` string - let's call it `notifyGameSpeedChanged`.
* It also calls a function that is somewhat similar to `getSpeedForSetting` I've discovered before, but with some extra conditions and code paths - let's call it `getSpeedForSetting2` for the lack of better ideas.
* Then it uses similar fuzzing trick to get some other singleton (I've called it `Timing`, but it's actually a bad name, I will rename it later) and calls some virtual functions on it (let's call the relevant one `setSpeed`).
* I've called it `setSpeedFromUI`.

Ok so then let's emulate what `setSpeedFromUI` does - let's call `setSpeed` to modify `TimingData`, `Timing->setSpeed` to modify `Timing`, and override `getSpeedForSetting2` to return the same constant.
This works - the game now runs extremely slowly, the timers run extremely slowly, units move slowly - that's great! However, game still crashes after a while (this is not great).

Oh and also the animations and vfx slow down too. In fact, at this point I've realized that in the actual game vfx/animation speed depends on game speed setting!
While this is reasonable for things like shooting animations, it looks awful for things like movement destination animation - and with extremely low game speeds, it just looks like awful bugs.

## Catching crashes

Ok, further speed tweaks can wait - the crashes really need to be fixed first. I can't attach the debugger, but I don't really need to - I can just install VEH (vectored exception handler), catch all exceptions and log out the stacks. Then look up why it happens in IDA.

Immediate findings is that even without patching anything, there are some exceptions happening that don't lead to a crash. The `EXCEPTION_BREAKPOINT` is especially common - it looks like a part of some anti-tampering logic.
It's caused by an `int 3` instruction in some small obfuscated function (let's call it `antidebug_int3`), and it's caller is some very large heavily obfuscated function that we'll call `antidebug_main`.

Just before the crash, there's a `EXCEPTION_ILLEGAL_INSTRUCTION` exception followed by `EXCEPTION_ACCESS_VIOLATION`.
The former is triggered by `ud2` instruction in another small function (let's call it `antidebug_ud2`), and it's caller happens to also be the caller of `antidebug_main` (and it also looks heavily obfuscated).
That caller in turn is called by some normally-looking function in a loop until it returns `true` - so let's call it `antidebug_tick`.

To summarize our findings:
* There's some normal function, which calls `antidebug_tick` in a loop, until it returns `true`.
* `antidebug_tick` calls `antidebug_main`, which calls `antidebug_int3`, which does a breakpoint - and it seems to be happening often and not directly related to crash.
* `antidebug_tick` also at some point calls `antidebug_ud2`, which does `ud2` - and it seems to be preceeding the crash.

The naive attempt to bypass the whole thing (hook `antidebug_tick` and have it return immediately) doesn't work - returning `true` just exits the game, returning `false` hangs it.

So it looks like I'll need to investigate these four functions properly next!

## Jump obfuscation

The very first thing in the `antidebug_tick` is the similar pattern to what I've seen in TLS callback - some conditional jumps to the middle of instructions. In fact, IDA can't even create a function there - pressing P manually just errors out.

On closer inspection, it becomes apparent that there's no magic here. The pattern is simple:
```
SC2_x64_CODE:00007FF6AFA8F4D7                     nop     word ptr [rax+rax+00000000h]
SC2_x64_CODE:00007FF6AFA8F4E0                     jnb     short near ptr loc_7FF6AFA8F4EC+3
SC2_x64_CODE:00007FF6AFA8F4E2                     xchg    bh, bh
SC2_x64_CODE:00007FF6AFA8F4E4                     jb      short near ptr loc_7FF6AFA8F500+4
SC2_x64_CODE:00007FF6AFA8F4E6                     mov     cl, 9Ah
```

So what's happening here is a conditional jump (`jnb` in this case) to some location X, followed by an instruction that's effectively a no-op (`xchg bh, bh` in this case), followed by the opposite conditional jump (`jb`) to location Y.

The instructions between two jumps don't affect flags, so there's no way to reach the instruction after second jump regardless of the initial state. So everything below is actually just junk - let's undefine it ('u') - and now first jump target is some normal location.
Let's define instruction there - it's a `nop` followed by another `jnb`! Again, everything after this is junk (since X could only have been reached by `jnb` and flags aren't changed by nops). Similar story for the other `jb` branch - it's a bunch of nops followed by `jb`.

Ultimately, both of these branches converge to a normal instruction. So effectively everything starting with the very first `nop` (or the first conditional jump) can be replaced with a simple `jmp` to the convergence point (using IDA's patch bytes feature), and then the junk code between them hidden from view.

This turned out to be an extremely common pattern used by different places in code, with some variations:
* Filler no-ops are literal `nop`, a move-to-itself or exchange-with-itself (`mov/xchg x, x`), a shift-by-zero (`sal/sar/shl/shr x, 0`).
* Another variation - single-route - starts with an instruction that changes only flags(`or/xor x, 0`, `and x, ~0`, `test x, anything`, `clc/stc`) followed by a series of jumps that are always taken because of the change.

In vast majority of cases (I've only seen one exception), the beginning of this sequence is aligned to 0x10 by real `nop`s (single or multi byte).
Any 'outside' jumps target the aligned beginning of the jump sequence after these nop sequences - so generally it's best to keep the nops in place when patching (otherwise external jumps might now lead to junk, breaking analysis).

Fixing these manually by hand is tiresome, so I've made a simple script (see `patch_jump.py`) that tries to interpret instruction sequence at cursor as a beginning of such jump sequence - and on success replaces it with a jump to the target, marking everything in between as junk.

With this script made, I could quickly go through all four of these functions - and after patching all the jump chains, the functions can be created normally - and hexrays starts working - yay!

In general, this anti-tampering measure is quite effective at breaking default IDA autoanalysis. I feel that IDA could do better here - it knows the semantics of all the instructions already (it needs that for hexrays), surely it can detect unreachable instructions after conditional jump that's always taken and not create code there?
Maybe that can be fixed with custom IDP module - I haven't tried it yet, but it should be possible from what I understand about how they work.

## Analyzing first antidebug function

Let's start with simplest one - the `antidebug_int3`. It starts with one jump chain, and after patching it it's really small and simple:
```
SC2_x64_CODE:00007FF6AFA1A360 000                 mov     rdx, rcx
SC2_x64_CODE:00007FF6AFA1A363 000                 jmp     short loc_7FF6AFA1A3D0
SC2_x64_CODE:00007FF6AFA1A363     ; ---------------------------------------------------------------------------
SC2_x64_CODE:00007FF6AFA1A365     ; Junk code
SC2_x64_CODE:00007FF6AFA1A3D0     ; ---------------------------------------------------------------------------
SC2_x64_CODE:00007FF6AFA1A3D0
SC2_x64_CODE:00007FF6AFA1A3D0     loc_7FF6AFA1A3D0:                       ; CODE XREF: antidebug_int3+3?j
SC2_x64_CODE:00007FF6AFA1A3D0 000                 mov     cl, 1
SC2_x64_CODE:00007FF6AFA1A3D2 000                 mov     [rsp+arg_0], 10B3h
SC2_x64_CODE:00007FF6AFA1A3DB 000                 mov     rax, [rsp+arg_0]
SC2_x64_CODE:00007FF6AFA1A3E0 000                 xor     rax, 10D7h
SC2_x64_CODE:00007FF6AFA1A3E6 000                 mov     [rsp+arg_0], rax
SC2_x64_CODE:00007FF6AFA1A3EB 000                 mov     rax, [rsp+arg_0]
SC2_x64_CODE:00007FF6AFA1A3F0 000                 mov     [rsp+arg_0], rax
SC2_x64_CODE:00007FF6AFA1A3F5 000                 mov     rax, [rsp+arg_0]
SC2_x64_CODE:00007FF6AFA1A3FA 000                 mov     [rdx], eax
SC2_x64_CODE:00007FF6AFA1A3FC 000                 int     3               ; Trap to Debugger
SC2_x64_CODE:00007FF6AFA1A3FC                                             ; try ... except (0x1) 0x7ff6afa1a3ff
SC2_x64_CODE:00007FF6AFA1A3FD 000                 jmp     short loc_7FF6AFA1A410
SC2_x64_CODE:00007FF6AFA1A3FF     ; ---------------------------------------------------------------------------
SC2_x64_CODE:00007FF6AFA1A3FF
SC2_x64_CODE:00007FF6AFA1A3FF     seh_handler_0:                          ; CODE XREF: antidebug_int3+9C?j
SC2_x64_CODE:00007FF6AFA1A3FF 000                 mov     dword ptr [rsp+arg_0], 0 ; ^^ end try
SC2_x64_CODE:00007FF6AFA1A407 000                 mov     eax, dword ptr [rsp+arg_0]
SC2_x64_CODE:00007FF6AFA1A40B 000                 test    eax, eax
SC2_x64_CODE:00007FF6AFA1A40D 000                 setnz   cl
SC2_x64_CODE:00007FF6AFA1A410
SC2_x64_CODE:00007FF6AFA1A410     loc_7FF6AFA1A410:                       ; CODE XREF: antidebug_int3+9D?j
SC2_x64_CODE:00007FF6AFA1A410 000                 movzx   eax, cl
SC2_x64_CODE:00007FF6AFA1A413 000                 retn
```

The interesting bit here is what happens when `int 3` is executed. Normally on windows, it will first go through registered VEH handlers, then if not handled there it will do SEH lookup based on instruction address to find the handler.
There are great in-depth explanations about how SEH works, not going to repeat it here.

Let's see if there's any SEH handler for this `int 3`. Following the header fields, I find that:
* The function itself has an exception handler, and it looks to be the standard C++ one from MSVC. The source can be found among CRT sources.
* There's a scope table with a single entry that covers `int 3` and following jump.
* The exception filter is just 1, standard MSVC SEH handler special-cases that to mean 'always execute handler'.
* The exception handler is right at the end of the try-except block.

Taking all that into account, this is how the function works:
* First it sets cl to 1 and `[rsp+arg_0]` to 0x10B3 ^ 0x10D7 == 100
* Then it executes `int 3`, and if everything is well SEH transfers control to the handler.
* The handler sets `[rsp+arg_0]` to 0, then reads it back and sets cl to 1 if it's non-zero and 0 otherwise (so normally to 0).
* Finally it returns whatever is in cl (so normally zero).
* If something went wrong (eg instead of transferring control to the handler, something else - like a custom VEH handler - tries to continue execution), then the function would return 1.

The caller (`antidebug_main`) executes some logic if `antidebug_int3` returns non-zero - presumably it's a reaction to detected tampering.

So the intent here seems to be to check periodically that nothing fucks with `EXCEPTION_BREAKPOINT` handling. I suspect it's intended to detect some debuggers - they would stop on breakpoint, and pressing continue would continue normal execution and avoid SEH handler.

In any case, this is not relevant for me at all, so I can just pass this exception in VEH handler transparently, without logging all this noise.

## Analyzing second antidebug function

Now let's look at the `antidebug_ud2` function. After fixing jump chains, it's also quite simple:
* It spills the four register args to stack and executes `ud2` instruction.
* It uses standard MSVC SEH handler, and `ud2` is covered by the try-except scope. This time the filter is an actual function.
* Right after `ud2` there's a jump, and SEH handler jumps there too - and after executing some code this ends up doing `int 29h`, which is `__fastfail`.
* Since the process doesn't end with fastfail, this suggests that SEH filter does something interesting.

Now, analyzing SEH filter is a bit of a pain - it's an independent function, but it gets the pointer to the original's function stackframe, and actively uses that. IDA doesn't really support sharing stack between functions (as far as I know? couldn't find a way to do that, at least...).

Still, I can define a 'stackframe' structure manually. Then it becomes apparent that the filter does a whole bunch of manipulations and ends up modifying the register values in the `CONTEXT` structure - including modifying `RIP`.

Now, the code looks complicated, but in reality it's a whole bunch of bullshit. The function has 11 parameters, last 8 are algorithm+parameter pairs.
For each pair, it modifies the accumulator (adding/subtracting/xorring with corresponding parameter, depending on algorithm) - and then reverses everything, leaving accumulator equal to 0 regardless of inputs. It then assigns this zero to a register in `CONTEXT` structure and repeats for next register.
So ultimately it effectively zeroes out most registers, including `RIP`. Then filter returns `EXCEPTION_CONTINUE_EXECUTION`, which jumps to zero and causes `EXCEPTION_ACCESS_VIOLATION`.

Ok, so this is the real source of the crash. Now, let's see what calls it - it's `antidebug_tick`.

## Analyzing third antidebug function

The next function is `antidebug_tick` - it's decently sized, so manually fixing all jump chains takes a bit of time here. However, once that is done, hexrays shows that it's not too complicated. It does a few interesting things.

### First block

First, it reads some field of a structure at 0x7FFE0000. On windows, this always contains a `KUSER_SHARED_DATA` structure, which is well documented by various sites on the web.
Defining it manually in IDA (for whatever reason, it's not there in standard structures) and setting the type at the address, it becomes apparent that the code checks whether any of the two low bits of KdDebuggerEnabled field are set (implying that kernel debugger is active).
If so, it calls some function that looks very similar to `antidebug_ud2` I've just looked at. This version accepts 13 arguments rather than 11, but frankly it does not matter - the intent is clear, if kernel debugger is active, it crashes here.
I don't use kernel debugger, so it's irrelevant for me now - but still it's good to know what to expect!

### Second block

The next block is executed if `rdtsc() % 100 < 5` - this seems to be a very common way SC2 uses to rate limit it's antitamper checks, make them happen on some ticks pseudo-randomly - with 5% probability in this case.
Then it checks whether some global is non-null (it's non-null in the dump), and if so - starts doing a whole bunch of magic, with hardcoded constants, xors and shifts.

The global has tons of references, and it seems to be related to anti-tampering - so let's create a structure called `AntidebugState` and figure out what this magic does.

First thing it does is save some large 64-bit constants on stack, and call some new function passing their addresses as arguments. This function, as usual, needs to have its jumps cleaned up - but then it becomes apparent that it's quite simple.
The main thing it does is perform some transformation on its inputs:
```
*a2 = __ROR8__(0xF3791823EBD0BA08ui64, 12) - *a2;
*a1 ^= ~(__int64)NtCurrentPeb()->ImageBaseAddress ^ 0xF3791823EBD0BA08ui64;
```

The other thing it does is check the return address, and if it's not coming from SC2 code section, it zeros out a page containing PEB in an endless loop. Ouch :)

So it's clear that the intent of this function is to do some obfuscation. The transformation it does is symmetric (so calling it twice is an identity transform on the arguments), and it has tons of references - it seems to be a very common utility for anti-tampering code.
Let's call it `antidebug_obfuscate`.

As for the return-address check - the intent for that is clear (prevent injected code from calling it), but tbh I think it's really pointless:
* It's simple enough to be just reimplemented by the injected code, it's literally two lines.
* Even if it were not (the similar return-address checks will be encountered in many more places in SC2 code), it's trivial to patch out.
* It's really unlikely to be an unexpected surprise for a reverser - one has to first find and understand what the function *does* before one gets an idea to use it, but by then one already knows about the return-address check, since it's extremely obvious.

Now let's go back to the second block of the `antidebug_tick` and work through the maths manually. This takes a few minutes, but by the end it becomes apparent that this code takes the field of `AntidebugState` at 0xC40 and converts it into an address of a function, and checks whether it's zero.
If not, it repeats the whole thing again and calls the function with some arguments.

Let's take a look at this function - ok, it's a syscall 0x19. Googling a bit, I've found this awesome table: https://j00ru.vexillium.org/syscalls/nt/64/ - and it tells that this syscall is `NtQueryInformationProcess`. Let's look up its implementation in the ntdll - yep, it's exactly the same.
Looking at the arguments for a call, it asks for information class 30, which is not documented on MSDN, but described elsewhere to be `ProcessDebugObjectHandle`.

So then, the next condition is true either if process is being debugged, or we did not call `NtQueryInformationProcess` for some reason (antidebug state being zero or having zero function pointer after deobfuscation).
Let's call the `AntidebugState` field at 0xC40 `xorredNtQueryInformationProcess` and look at what happens if process is being debugged.

After some more calculations, it becomes apparent that it reads `AntidebugState` field 0xB48, decodes it with a new set of constants to be equal to address of `ZwAllocateVirtualMemory`, allocates some memory, fills it with a code snippet and calls it. The code is not that interesting, it just crashes the process.
And if for whatever reason the emitted code returns, it does `__fastfail`.

Again, since I don't use debugger, it's irrelevant - but good to know!

### Third block

Next block is executed if `rdtsc() % 100 < 30` (so on 30% of ticks). It's a bit bigger, let's see what it does:
* First, it calls `antidebug_obfuscate`, and one of the arguments is some global (some encryption key). Then it reads 6 qwords that are in memory right before the encryption key, and performs some maths on it (presumably, decrypts a structure).
* Then it checks some conditions on the fields of the decrypted structure. If the condition passes, it enters some inner block - and this inner block is very interesting, because it contains the call to `antidebug_ud2` function that causes a crash. So this looks important.
* If the condition does not pass, it instead does another rate-limiting check `rdtsc() % 100 < 5` - and does something else with the structure.

Let's look at the first sub-block first, the one that ends with a crash. The conditions are interesting:
* First condition checks whether windows version is 'new enough', and if so - calculates `((g_KUSER_SHARED_DATA.TickCountQuad << 8) * (unsigned __int128)((unsigned __int64)g_KUSER_SHARED_DATA.TickCountMultiplier << 32)) >> 64`. Reading up on these fields, this matches what `GetTickCount` should do - this looks like inlined version.
* Then it compares second qword of the decoded structure - so it looks like this field contains the time until which the block execution is delayed.
* The fields at 0x10 and 0x20 also have to be non-zero for the crash to happen.
* Right before calling crash function, there's a code that reads stack bounds from TEB, and then fills the entire stack except a page on one side and a small random number of bytes on the other side with random values (all randomness derived from rdtsc).

That last stack trashing logic is interesting, I think it's supposed to make stacks at crash point incomprehensible - but since it doesn't touch the bottom-most page, and this code happens close enough to the bottom of the stack, it does not actually do anything meaningful.
If it were implemented more carefully, it would make the analysis up to this point quite a bit more complicated...

Now the second sub-block, the one that happens on 5% ticks if we don't crash:
* First it does CAS loop to lock some spinlock, located right after encryption key in memory.
* Then it decodes the structure again.
* Then it modifies the first qword by some pseudo-random (based on rdtsc) transformation
* Then modifies the encryption key pseudo-randomly.
* Finally it reencodes the structure with the new key, and unlocks the spinlock.

Note that write is protected by spinlock (implying potential concurrent access), but read is not (implying that only thread executing this function can modify this structure, or maybe that there are data races in the code...).

Before continuing on, let's add some code to log the state of this structure in the function hook. The decryption logic has to be reimplemented carefully. Running the game and looking at the spam, it becomes apparent that:
* First field changes very often, and seems to contain random junk. This matches what I'd expect from the last sub-block implementation.
* The other stay constant, and also look meaningless. Notably, second qword is much larger than whatever `GetTickCount` returns - it's so far in the future that the first check around crash block never succeeds.
* At some point, things change - second qword becomes equal to `GetTickCount` plus several seconds, and other fields get more reasonable (small) values. The dword at 0x1C becomes equal to 300.
* From that point, first qword continues changing randomly, and other fields stay the same.
* As soon as tick count reaches the threshold, the game crashes.

So the hypothesis is that - when some other code detects tampering, instead of crashing immediately, it encodes the failure in this structure, and schedules it to crash after some delay.
That's a neat idea - this multi-second delay is probably aimed at making it harder for a reverser to understand how his changes cause the crash.

For now, let's call the structure `DelayedCrashState`. First qword is trash, second qword is scheduled crash time, others are unknown for now. The dword at 0x1C looks interesting - could it be that blizzard decided to help reversers by storing the reason of the crash there?
Let's call it `reason` for now :)

### Rest of the function

After the third block, the function calls a few other functions (including `antidebug_main`) and finally returns the value of some global. The first one does some timer calibration, and then calls some other function that contains some strings mentioning bad profiling data.
Hmm, it's strange - why does anti-tampering function call something related to profiling?.. Anyway, maybe thing will become more clear after last function is analyzed.

## Analyzing fourth antidebug function

The last remaining function is `antidebug_main`. This one is quite large, cleaning up all jump chains takes a bit of time (this is getting annoying). However, even after that, IDA autoanalysis has issues with it: hexrays doesn't work, and it complains about sp-analysis failing.

The function seems to require a lot of stack - more than a page - and it calls a small function with a special calling convention that ensures stack is grown appropriately (touches each page one by one). Normally IDA handles that automatically, but here it did not, probably because it's analysing a dump.
No big deal, it's easy to fix by manually adjusting sp deltas where needed (alt-k), and then manually adjusting function's stack properties via alt-p.

With that, analysis succeeds, and hexrays works somewhat. The only remaining issue is that function uses AVX2 instructions, and for that to work correctly, it manually aligns rbp to 0x20 - and this seems to break hexrays, it can no longer determine stack vars properly.
I don't know how to fix that, this is annoying, IDA really dropped the ball here :( Oh well, can still analyze things without that, even though it's way more annoying.

### Constant propagation script

This function also accesses the fields of `AntidebugState`, with similar patterns (a whole bunch of maths to decode it). By now I'm sick of decoding that manually, it's time to implement a script that does this calculations automatically.
The result is `constant_propagation.py`, it's basically an emulator for a subset of x64 instructions used for encoding. This will speed up future analysis significantly.

### First block

First thing it does is execute inlined `GetTickCount` (with old windows version check), then check whether at least 1 second has passed since last check (storing the previous value in a global).
If so, it increments a field of `AntidebugState` at 0x1C8 (after decoding it, and then reencoding it back, with a few xors) - let's call it `xorredSecondsCounter`. It then compares it against other field (0x104, `xorredSecondsThreshold`), and if it's greater, sets some flag.
The next condition checks this flag and if set, does a familiar `ud2` -> crash sequence.

This doesn't seem relevant for now, but at least I have a new fields in `AntidebugState` that I need to keep in mind.

### Second block

The next block is familiar. It is rate limited (`rdtsc % 100 < 5`), and it calls `antidebug_int3` to check for interference from debugger. If tampering is detected, it does a familiar logic to fuck up the stack, allocate some memory and write a code there which crashes the game. Nothing interesting here.

### Third block

The next block is also rate limited (`rdtsc % 100 < 30`), and it's a big one, with two nested loops. Let's see what happens there:
* Reads and decodes `AntidebugState` field 0x100 (equal to 0x7FDE). Then calculates a pseudorandom value and calculates modulo this value. This looks like a starting index, and the value at 0x100 is a count of some things.
* Then it checks a bunch of flags and initializes some variable to either 8 or 16, before starting loops.
* The inner loop has a counter and breaks if it reaches field 0x100 - this supports the idea that it's a count of things to check - and then starting index is random, and 8/16 is the number of things to check.
* Then the code decrypts `AntidebugState` field 0xF8, which is some address on a heap. This seems to be some sort of an array, and the current index is used to look up a value. The value then is decrypted again, and the loop continues to the next index if decrypted value is 0.
* Looking at the array in memory, the first entry happens to be encrypted zero, and there are many other 'zeros' close to the end.
* If array entry is non-zero, the code decrypts `AntidebugState` field 0x50 - it happens to be equal to the exe image base.
* And then, depending on the combination of global flags, it calculates the hash of the i'th page and compares it to the entry in the array.
* It then continues to verify hashes for 8/16 pages, unless some mismatch is found.
* If a mismatch is found, it executes a familiar piece of code - it locks the delayed-crash spinlock and writes a new delayed-crash structure. The scheduled crash time is 120s + random value from now, and the `reason` field is set to 300.

### Page hash check

This is amazing luck! Almost accidentally I've found the anti-tampering mechanism that detected my hook (since it modified some page of the code), it even set the reason field correctly! Blizzard indeed cares about reversers, giving such an obvious hint.
Let's quickly name the relevant fields of `AntidebugState` (`xorredNumPageHashes`, `xorredPageHashAddress`, `xorredImageBase`), and without wasting time write a patch to skip this page hash validation logic.

I still can't believe it was so easy, in fact - I only touch a few pages, and this check is rate limited, how come it can find the tampered page so quickly?.. Doesn't matter, no time to think, need to patch!

Applying the patch, running the game, ... and it still crashes. With the same reason 300. Oh well.

Looking at the code again - I notice that when the mismatch is found, there's a small check - it reads a global, checks that it's pointing inside SC2 code section, and if so - calls it as a function. Looks like some `antidebug_page_hash_mismatch_callback`.
It's zero in the dump, though - probably some leftover utility to debug anti-tampering?..

But the important thing is I can 'x' it - and apparently there's another reference! It looks like another anti-tampering function, that fully duplicates page hash check logic. It also checks some other `AntidebugState` fields (nothing interesting), and calls a bunch of other functions at the end.

At this point I start suspecting that these are not dedicated anti-tampering functions - but rather, some normal functions that have anti-tampering checks injected at their start...

No matter, let's patch the second function too - and, again, getting the same crash.

If there are two copies of the page hash check, maybe there are more? The autoanalysis failed to find many functions, so let's run the simple script I've used to find string references again, this time to look for references to this callback.
Indeed, there are more references - several dozens! Carefully patching all of them is going to be tedious...

That also explains why it found the tampered pages so quickly - there are multiple places doing this check. I wonder, what's the total performance cost of this anti-tampering?..

If patching the code is complicated, how about patching the *data* instead? Say, let's set the `AntidebugState.xorredNumPageHashes` to 1 (encoded, of course) - in such case, every instance of page hash checking code would always check first page (image header) only.
In fact, image header is not hashed (corresponding page hash entry is decoded to zero), so it should early out after single iteration. That might even improve performance a bit, lol.

Doing that, running the game, ... and it crashes. But hey, the reason is different at least! In fact, in different attempts I've seen reason 301 and 310, implying there are at least two more checks to find and disarm.
So at least the page hash checks are now dealt with, that's a win!

### Rest of the function

Looking back at `antidebug_main`, after the page hash checks, there is a familiar pattern - whole bunch of calls, some of these seem to be doing some time tracking.

Now, since I have this suspicion that it's not a dedicated antidebug function, and looking again at the stacks I've seen - this happens in the main thread, everything above `antidebug_tick` are just normal functions without loops, and `antidebug_tick` is called in a loop until it returns true...

It sounds like `antidebug_tick` is in fact the main game loop! And it returns true when the game is to exit - this explains what happened with my first attempt to hook it. And `antidebug_main` is a nested function that actually contains the bulk of the main loop.

Let's rename the functions to `game_loop_tick_outer` and `game_loop_tick_inner`.

## Progress so far

One other thing I did around this time (after finding about stack corruption logic) is a simple utility that runs on the first tick after injection (on main thread), grows the stack by a few pages, and then write-protects the bottom pages.
This allows VEH handler to execute before stack is corrupted. However, this didn't really give me any useful insight.

Other than that, I know a few bits now:
* Anti-tampering seems to be injected into the beginning of a few key functions. The same checks are sometimes duplicated into many functions, supposedly to make patching them harder.
* Some types of anti-tampering don't crash the game immediately, but rather schedule a crash to happen in a few minutes. Sneaky!
* The jump obfuscation really breaks IDA autoanalysis, too much code is not treated as code properly, meaning that tons of crossrefs are missing.
* However, there's a huge chunk of SEH data, which should allow to identify hundreds of thousands of functions automatically (most of the functions, except for very simple ones that don't need any unwinding).
* There are quite a few anti-debugger techniques, it's probably easier to continue building ad-hoc debugger rather than trying to figure out what else breaks.
* In fact, what I really miss is breakpoints - especially memory-write breakpoints! And with VEH, they should be really easy to implement!

## SEH analysis

Let's tackle the terrible analysis results first, and try to improve it using data in SEH handlers. Finding SEH records is easy (just follow fields in PE structures in the header), and that array is *huge* (250k+ entries). Time to write a script!

First it needs to find function bounds. Often one entry covers one function, but sometimes there are multiple entries per function - the first one then contains exception handler info, and others have `UNW_FLAG_CHAININFO` flag set.
The script needs to read these to accurately determine function end.

Script doesn't really care about unwind data, but it does care about exception handlers! For the standard MSVC SEH handler, it can also parse the scope-table structures, and add some annotations that describe try-except / try-finally blocks.
For simplicity, I've had the script do the following:
* For each function with SEH handler, add a function comment with handler address (so I can double-click it quickly), and add a crossref from handler to the function.
* For each try block, add a regular comment on the block start/end with filter & handler addresses, and add a crossref from filter/handler to the block start.

These comments and crossrefs turned out to be so convenient! I wonder why doesn't IDA have something similar out of the box...

Now, to properly create functions, the script also needs to patch all jump chains. That's good, doing that manually for every jump was getting annoying. So with some experimentation and testing, the script is ready (see `seh_parse.py`).

Running it on the full array of SEH data took a while. I left it running overnight, and it wasn't done by the morning. It did finish when I returned from work in the evening. Oh well, at least it worked! The database now looks *so* much better...

There were a few functions in the SEH data that contained utter junk. I suspect these were real functions during bootstrap, that got trashed when the binary was loaded? Didn't really investigate it further...

## VEH debugger

Time to implement memory-write breakpoints. The idea is simple:
* I can mark the page I want to monitor as read-only.
* When someone tries to write there access violation will happen, which would be caught by my VEH handler.
* VEH handler can then check the fault address, see whether that's interesting one or something irrelevant just happening to share a page, restore the protection to read-write, modify the context to set single-step flag, and return `EXCEPTION_CONTINUE_EXECUTION` to execute the write again.
* Because of single-step flag, after the write we'll get `EXCEPTION_SINGLE_STEP` that VEH will catch again - it can then execute a callback if write touched interesting address, and mark the page as read-only again.

This will not *really* work well with multithreaded access (there's an inherent race between changing the protection when thread A does access and thread B trying to write data there), but who cares, it's good enough for me.

While implementing that, one worry I had was how to ensure no one intercepts my single-step exception. As a precaution, I've had VEH handler uninstall and reinstall itself as first handler before returning.
I was not sure whether it's actually legal to do so, but reading through the disassembly of the ntdll's exception dispatch function, that seemed to be safe (at least if I didn't care about thread safety).

This turned out to be a really good decision, I've later found some other anti-tampering function that would periodically uninstall & reinstall its own VEH handler that would specifically catch `EXCEPTION_SINGLE_STEP` and increment some counter in `AntidebugState`.
And then some other function would check it and crash if it was modified.

Nice, another anti-tampering feature was avoided without even knowing about it!

## Crash reason 310

Ok, let's use this new VEH debugger to catch delayed crash state modification. Easiest is to set a breakpoint on a spinlock, and run some code when it's set to 0. The code can then decode it (by now it's consistent) and print the reason and the stack.

The first thing it catches is reason 310, so let's look at it first.

The function does another debugger check, this time by looking at `BeingDebugged` flag in PEB. Eh, who cares, who needs debuggers anyway, we have better tech now.

Then the actually interesting block. It's rate limited (5% of calls), selects a random entry from a global 5-element array, the element contains 3 qwords. The first qword is decoded - running constant propagation script 5 times with different indices, these are starting addresses of each of the 5 segments for exe.
Then it decodes `AntidebugState` field 0xC58 - turns out to be an address of `NtQueryVirtualMemory`. It calls that for the selected segment, and then validates the result - checks that region size and protection matches whatever is encoded in other qwords.
If the check fails, it schedules the delayed crash with reason 310 - this is what happened.

Then the function does the familiar page hash check, and then executes some real code.

No big deal, two equally easy ways to fix this. The code can be patched to skip the check - but I have no idea whether it's duplicated anywhere, like the page hash checks.
Or the data can be fixed. I touch first two segments (code and data, latter because of VEH breakpoints), and don't touch others - so I can just copy last segment data into first two entries of the global array - this way first two segments will never be checked.

With this done, I no longer observe 310 crashes, but there are still 301's to deal with.

## Crash reason 301

This one is slightly more interesting - it's coming from non-main thread. In fact, this one seems to be some sort of a dedicated tampering detection thread - it runs an endless loop, does nothing except anti-tamper code, and three functions above it in the stack are trivial wrappers.
Let's analyze the loop a bit more.

First, it sets the `AntidebugState.xorredSecondsCounter = AntidebugState.xorredSecondsThreshold - 20`, and then sleeps for 2.5 seconds (using `WaitForSingleObjectEx`, the address of which is encoded in `AntidebugState` field 0x7B0).
Remember that the main loop increments the counter every second and crashes when it reaches the threshold - so it seems to be a check that anti-tamper thread is alive. This means if I want to kill it, I also need to patch out the check in the tick.

Then, it checks whether first entry in TLS callback array is the function that caused me some grief at the start (both array and function are encoded in `AntidebugState`). If it's not there, it will do a delayed crash with reason 380.
Good thing I restored it after injection! Another anti-tampering feature bypassed without even knowing about it, just by being careful to leave little traces when injecting!

Finally, it does some hashing - but instead of hashing a random page, it hashes the page hash table itself (and compares with expected result, stored in some global), and then hashes a part of the `AntidebugState`.
Since I've changed the `numPageHashes` field (which is inside hashed part of the structure), both checks now fail - and they trigger the 301 crash.

This time I've decided to simply patch out these checks completely - my hypothesis is that, since this is done in a special function, it's not likely to be duplicated.

And with that, all the crashes are now gone! I can inject a DLL into running SC2 process, fuck around with speed, and it will happily continue running. Huge success!

All in all, it was great fun - much more fun than whatever game designers could come up with :)

## Game

The rest is much less interesting, it's basically a normal reverse engineering process - figuring out how to implement the RTWP mode. The code is mostly self-explanatory, I'm just going to write about some key highlights.

### Slow mode

Going back to the idea of modifying game speed - let's now make it properly triggered by user interaction. Find and hook wndproc, enable/disable when player presses some button. It works nicely for a slow-mode (say 1/4 of normal game speed).

However, it starts really breaking for bigger slowdowns. Even something like 1/16 speed feels wrong (mostly because of animation slowdown), there's a weird pause when restoring normal speed, plus real-time timers act strangely.

Digging a bit more, it becomes apparent that SC2 handles real/game time in an extremely weird way:
* The game simulation runs at a fixed 16fps tick rate. The main loop increments 'unsimulated' passed time, as soon as it reaches a threshold (256 fixed-point units, or 1/16 of a second) it ticks the game simulation.
* The unsimulated time is scaled by game speed - so if game speed is set to 1/4, the simulation tick will be called every 0.25s.
* The simulation tick increments 'game time' by 256, and 'real time' by 256 multiplied by inverse speed.
* So effectively, if you make the game run very slowly (say at 1/128 rate), the 'real time' will be incremented by 8s every 8 seconds, rather than counting up smoothly.

So while tweaking game speed is fine for a modest slowdown, it's not at all suitable for true RTWP mode.

Some other things like changing global time scale also start causing problems if the rate is low (eg orders given during pause are cancelled with an error after a few seconds).

### Finding more tweak points

I've used a simple approach to quickly find functions to hook. I've made a test map with a trigger that called `SetGlobalTimeScale` on a condition (chat message), then hooked `SetGlobalTimeScale` and printed out a stack.

Looking through the stack, I've found a function with massive switch statement - that looked like a primary trigger action dispatch function. With some mid function hooks, I've now started logging out id for every executed action.
At that point I can add more triggers in the editor, see what internal id corresponds to the action, and see what functions it calls.

This gave me more useful info:
* How pause mission timer action is implemented (sets a flag in `TimingData`, which makes simulation tick not increment a value).
* How pausing/resuming a timer works: where list of active timers is stored and what is it's structure. This is useful - because timers tied to game time use the game time variable incremented by simulation tick function.
* Where units are stored (a global lookup table, storing pages of 16 unit structures, with individual page addresses encoded with a huge algorithm) and interesting fields of units (max speed, current speed, acceleration).
* Funnily, unit position is encoded again in the unit structure. Not sure why do they bother - maybe to protect against people who try to find it by scanning memory for increasing/decreasing values?..

Using VEH debugger to monitor current-speed changes for a specific unit, I've found a code that is responsible for acceleration.
It's very simple and doesn't actually care about the time rate - it's simply called once per simulation tick, and just applies the acceleration once.

### Actual pause implementation

The next attempt is to simply hook the simulation tick and immediately return when pause is active. Funnily enough, that actually kinda works! The only issue is that animations/vfx are frozen, which doesn't look great (you issue move order and see this permanent green arrow).

Ok, but what if during pause I increment game time and skip everything else? And turns out this works even better!

There are only two issues now:
* When the game is resumed, all active timers tied to game time instantly catch up.
* While paused, the moving units repeat the movement/rotation interpolation, which looks weird.

The first one is easy to solve - just iterate over active timers and fix them, as if they are paused.

The second one is a bit trickier. To start off, there's a trigger action to set unit position, which can be done immediately or with blend - let's see what calling immediate version right as I pause does to the issue.
Finding the function is easy (using trigger action dispatch hook described above). The function accepts new position and blend flag, and has two branches depending on the blend flag - let's investigate what I'll call `Unit::setPositionImmediate`.

I'll need to pass a new position there - and ideally I'd just pass current position, but I need to decode it first. Quick search doesn't find a function that simply returns a decoded position (understandable, it would be hilarious otherwise).
There's however another function that calculates distance from unit to point - let's just butcher it, by patching out the distance calculation bit at the end and simply returning position, then call it for a hardcoded unit #1 while injecting, log out position, and patch back.
After that is done, I know what to set - and then just hardcode set-position for unit #1 to known coordinates on pause. Trying it out - I can see that the interpolation stops. Ok, I'm on the right track.

Now let's find what exactly is responsible for stopping the interpolation. It can't be position change (we don't actually change it), but `setPositionImmediate` does a whole bunch of extra stuff.
So I do the really stupid hack now - I create a new function that does the same preamble (allocating stack frame, saving registers etc) and then jumps into the middle of `setPositionImmediate`. And then do a few attempts, changing the jump target, to see what's responsible for stopping the interpolation.

This quickly gets me a candidate - let's call it `Unit::stopInterpolation`. Now, let's call it for all units on pause - and it works. Yay!

And that concludes the effort.

## Not so fast!

Ok, now that I have everything working, I can finally play the game! Booting up Mass Recall map... and it crashes again.

This is another delayed crash, now with a new reason 320, haven't seen this one before. I have a stack, so I know what function sets up the delayed state. It also has all jump chains patched, so F5 works immediately. Let's see what it does.

First is the already familiar manual GetTickCount implementation, followed by decoding `AntidebugState` field 0x818, which contains address of a real `GetTickCount64` function. The code calls it, compares the results, and crashes immediately if it's bigger than 7.5s.
Neat, but irrelevant for me.

After that it does something interesting (containing the block that sets 320 delayed crash), and finally it has a copy of the delayed-crash handling code I've already seen in main tick function.
Let's look at the interesting block. It's rate limited to 5% frames, and then has an extra check - even if it detects tampering, it only actually sets the delayed crash state if hash of the process id satisfies a 50% check. Ok, this probably explains why I didn't see it before - got lucky with process ids.

The actual tampering check:
* Decodes two fields from `AntidebugState` (0x570 and 0x578). These both are some pointers, former to somewhere in code section (which doesn't seem to contain code), latter to some heap block.
* Generates a random index < 4095, reads a byte from first buffer, adds a random value to a byte in second buffer, compares the value in the first buffer with what it read before, and then restores original value in the second buffer.
* The crash block is executed only if comparison was true.

Both buffers look identical. So it seems that the code checks whether write into second also affects first - i.e. expects both pages to be mapped into same memory.
I did remap the code section before, so that I can inject - this explains why whatever custom mappings they've had are now broken.

Let's just patch out the change. Of course, I could also restore the mappings - or even better, just change one of the fields so that they decode to same pointer - but that would require replicating the encoding logic. That's more work, let's do that only if I find that the check is duplicated in multiple places.

## Deeper dive into obfuscation

While poking around the dump, I've found an outlined version of the encryption function. It's a function in the static initializer table (used by CRT to initialize globals before `main` starts executing), it's #15 there, and it sets pagehash checksum to encrypted zero.
The function works like this:
* First, it takes two constants and applies `antidebug_obfuscate` to them - giving us obfuscated constants.
* Then, it does four rounds of transformation using another function I'll call `antidebug_primitive`.
** The first argument is either a constant or a value read from a memory block I'll call `antidebug_xor_constants`. It's always accessed by index < 4096 (either 12 low or 12 high bits of some value) and read as qword, so it's 4096+8 bytes in size. It's located between list of known threads and delayed crash state.
** The second argument is either high or low dword of input or a result of a previous round.
** The third and fourth arguments are constants.

The pseudocode of the function:
```
qword c1 = k1, c2 = k2;
antidebug_obfuscate(&c1, &c2);
qword key1 = *(qword*)(antidebug_xor_constants + (c2 & 0xFFF));
qword key2 = *(qword*)(antidebug_xor_constants + (c2 >> 52));
// aN are either low or high dword of k2, key1 or key2, at least I haven't seen any others
qword x1 = { in_lo, in_hi ^ antidebug_primitive(a1, in_lo, n1, n2) }; // { lo, hi }
qword x2 = { x1_lo, x1_hi ^ antidebug_primitive(a2, in_lo, n3, n4) };
x2 ^= c1;
qword x3 = { x2_lo, x2_hi ^ antidebug_primitive(a3, x2_lo, n5, n6) };
return     { x3_lo, x3_hi ^ antidebug_primitive(a4, x2_lo, n7, n8) };
```
Note that in this case `n7 == n1` and `n8 == n2`, but it's a coincidence.

One way to simplify that, if we note that every round of `antidebug_primitive` does not actually change low dword:
```
in ^= antidebug_primitive(a1, in_lo, n1, n2) << 32;
in ^= antidebug_primitive(a2, in_lo, n3, n4) << 32;
in ^= c1;
in ^= antidebug_primitive(a3, in_lo, n5, n6) << 32;
in ^= antidebug_primitive(a4, in_lo, n7, n8) << 32;
return in;
```
The important takeaway here is that low dword is actually not heavily transformed - it's just xorred with a transformed constant. This can be confirmed by looking through some examples of similar inlined obfuscation and results of constant propagation.
It also explains why the few dword fields in `AntidebugState` are encoded with a simple xor - all these rotations etc are optimized away, because they would only affect high dword.

Another important nontrivial conclusion is that to invert the encryption, one just needs to apply all these xors in reverse order: only low dword of the value is used as an argument, and only high dword is affected by xor.

Now looking at `antidebug_primitive`: the signature is `uint (uint key, uint value, uchar op1, uchar op2delta)`. It performs two operations:
* First, it calculates intermediate value `uint inter` from `key` or `value`, depending on `(op1 + op2delta) & 7`.
* Then, it calculates the result from `value` and `inter`, depending on `op1`.

Pseudocode:
```
uchar op2 = op1 + op2delta;
uint shift = (op2 & 0xF) + 1;
uint inter = (op2 & 7) switch {
	0 => rotl(key, shift),
	1 => rotl(value, shift),
	2 => rotr(key, shift),
	3 => rotr(value, shift),
	_ => key
};
return op1 switch {
	1 => inter - value,
	2 => inter ^ value,
	3 => 2 * inter - value,
	4 => 2 * value - inter,
	5 => value - inter,
	6 => ~inter ^ value,
	7 => inter ^ ~value,
	_ => inter + value
};
```
It is now clear how one could reverse-engineer the constants from the inlined call (shift in rotate gives op2, what type of operation is perfomed later gives op1).

## Analyzing bootstrap code

After posting this, I've got a few DMs with various bits of useful info. One thing in particular that was interesting to me was that apparently SC2 has some part of the obfuscation that's machine specific. To find out more, let's take a deeper look at the initial boot flow.

### Phase T

Opening the executable binary in IDA again, with all the knowledge gained before, it doesn't look too bad anymore. The main entrypoint has some jump obfuscation going, but the script I've made before makes short work of it.
It then does the already familiar 'manual import' (searching loaded dlls by FNV hash of the name - `user32.dll` in this case - then searching for exported function by FNV - `MessageBoxW` in this case) and then shows an error. After that it similarly finds `ExitProcess` in `kernel32.dll` and calls it.
So everything interesting must happen before entrypoint, and if entrypoint is executed, it means the bootstrap process has failed.

The only interesting thing in the entry point is the error message - it uses the hardcoded string `Game Initialization Failed: #`, but replaces the last character with a value of some global. As we'll see later, this is a sort of 'initialization phase' tag.
The initial value is `T`. From now on, I'll call the phases by the tag name.

### Phase U

The next place to look for init code is obvious - if it is to be complete before entrypoint, it must be TLS. TLS directory has a single callback, IDA helpfully calls it `TlsCallback_0` automatically - let's look at it.
The first thing it does is set the init phase tag to `U`, and returns if the Reason is not `DLL_PROCESS_ATTACH` (fine, it's a bootstrap code).

The next block ensures the next 256k on the stack are committed. It finds the first module in the loader's module list (== the main executable), ensures it doesn't go below the `SizeOfStackReserve` minus 3 pages,
and then starting from retaddr on stack touches (reads) a byte per page until either reaching a limit or touching all desired pages.
This is probably done now to avoid interfering with VEH thing it will set up later.

Next thing it does is fills the 4104-byte (a page + 8 bytes) area with random values (here and everywhere else 'random' is based on rdtsc + some transformation). Cross-referencing the old idb, it's apparent that this area is `antidebug_xor_constants` - so this is what fills the encryption keys.

Next thing does CPUID instructions to determine processor features. It initializes the global flags I've seen before, checked in pagehash code. First 6 flags are generic capabilities (SSE, SSE2, SSE4.1, SSE4.2, AVX and AVX2).
Next two flags are copies of SSE4.2 and SSE2 support flags - however, these are checked in pagehash logic, so I suspect their meaning is `pagehash supports algorithm X` (and thus pagehash supports SSE4.2 if and only if processor supports SSE4.2).
The final flag is set if both AVX and AVX2 are supported and windows version is >= 6.3 - this is a `pagehash supports AVX` flag. I suspect the windows version check is needed here because some old windows versions didn't preserve full AVX state across context switches, or something similar.

Finally, it finds the TLS callbacks table in the executable module, manually finds `kernel32.dll` and `VirtualProtect` in it, and checks `PEB->NtGlobalFlags` for heap-check flags (i assume this is a debugger check).
If heap check flags aren't all set, it modifies the TLS callback table (since it's in rdata section, it changes protection to `READ_WRITE` before and restores original after).
In TLS table, it replaces the first function with something that looks encrypted, and then inserts two more entries (taking care to shift any further TLS callbacks, even though there are none).
The third TLS callback also looks encrypted, but the second is a normal function. Let's call these three functions `tls_bootstrap_0/1/2`.

It then returns, and since the new TLS entries were added, loader would call `tls_bootstrap_1`.

### Phase I

The second TLS function immediately sets phase tag to `I` and just calls the inner function `tls_bootstrap_1_impl`. This inner function immediately returns if `Reason` is not `DLL_PROCESS_ATTACH`.

The first thing it does is go through relocation table of the executable and gather all relocations that straddle page boundary into a global array. There are actually none, at least in the version of executable I was reversing - it will become clear why this is needed later.
The global array has enough space for 128 entries, if there are more such relocations - it will crash by doing divide-by-zero.

The next bit is a bit verbose, but not very interesting - it finds four different module entries in the loader's module list: the 'primary' (whose `DllBase` is equal to the function argument), the first in list (normally it's the same as primary), `kernel32.dll` and `ntdll.dll`.

Then it calls another function: `bool setup_veh(IMAGE_DOS_HEADER *kernel32, IMAGE_DOS_HEADER *ntdll)` (the name, of course, was chosen after reversing). This function again does some verbose manual imports, but essentially it's quite simple:
* Find `RtlAddVectoredExceptionHandler` in ntdll, check that it doesn't start with breakpoint instruction, xor with constant and store in a global.
* Then call it to register new VEH handler (let's call the function `bootstrap_veh_handler`) and store the returned handle in a global. I'll get to the VEH handler later.
* Find `CloseHandle`, `VirtualAlloc`, `NtCreateSection`, `MapViewOfFileEx`, `VirtualProtect`, `UnmapViewOfFile` and `RltRemoveVectoredExceptionHandler` in corresponding dlls, check that they don't start with int3, xor with their own constants and store in globals.
* If anything failed, returns `false`, and the caller instantly returns (this will lead to a crash).
* And finally if everything's good, execute `hlt` instruction, then return `true`.

Since `hlt` is a privileged instruction, it then transfers control to the VEH handler, so let's take a look at it.

### VEH handler

The installed VEH handler is a simple wrapper, everything is happening in the inner function `bootstrap_veh_handler_impl`. It only cares about two exceptions - `EXCEPTION_PRIV_INSTRUCTION` and `EXCEPTION_SINGLE_STEP`.
For `EXCEPTION_PRIV_INSTRUCTION`, it inspects what caused the exception and only handles `hlt` and `wbinvd`; it adjusts RIP to skip them. For anything else, it just returns `EXCEPTION_CONTINUE_SEARCH`.

Then depending on state, it either enables or disables single-step flag. So this makes the design clear:
* Privileged instructions are used to control VEH logic: `hlt` enables it, `wbinvd` disables it.
* When enabled, VEH forces itself to execute once per normal instruction by constantly setting single-step flag.
* VEH also keeps an invocation counter and disables itself after running 0x7E0 times (unless it was explicitly disabled earlier).
* The exit code and the argument (exception details) is kept in a global, xorred with constant.

Now, the payload logic of the VEH handler looks complicated (15 different subfunctions, and a few globals), but really most of that is just junk code, there's only one important thing VEH does, so let's analyze. I've called all subfunctions `bootstrap_veh_subN` for now.

All these subfunctions are similar in construction. Looking at the first one:
* Check if `dr7` register is non-zero (meaning any hw breakpoints active) - and if so, crash by changing RIP in context to point to `bootstrap_veh_continuation_bad` and RDX to 0 - the function would then attempt to read from a value pointed to by RDX and crash with AV.
* Count number of times it was called, return `false` if value is low enough (less than some constant plus some random value).
* At a certain number of calls, execute some logic.
* Crash if some global is set (`gBootstrapRegion_hash_mismatch`, described later).

Now specifics of these functions:
* sub1 at some point calculates the hash of a region (let's call it `gBootstrapRegion_start` and `gBootstrapRegion_end`, looking at addresses it encompasses the whole bootstrap code).
** If this is the first time it's hashed (`gBootstrapRegion_hash` is 0), save it in a global. Otherwise compare with global - and on mismatch set `gBootstrapRegion_hash_mismatch`. Finally, if `gBootstrapRegion_hash_mismatch` is set - crash.
** Also it sets a global `gVEHState1` to it's initial value (the main VEH function xors it with this later, so effectively it sets it to logical zero).
* sub2 is similar, except that is sets other global `gVEHState2` to its logical zero.
* sub3 reads some chunk of memory, xors it with other chunk of memory, and then does nothing with the result (unless I've missed something, this looks like pure junk). Also crashes on `gBootstrapRegion_hash_mismatch`, even though it doesn't actually hash the region.
* sub4 sets some other global `gVEHState3` (a byte this time) to a logical zero or one, randomly depending on rdtsc.
* sub5 is same as sub1, except that it sets `gVEHState1` to logical non-zero (the value that main VEH function later expects).
* sub6 is similar to sub4, except that it sets `gVEHState4` to a logical zero or one, randomly depending on rdtsc.
* sub7 is similar to sub3, except that it hashes a different region (and also does nothing with it).
* sub8 is same as sub2, setting `gVEHState2` to expected value (like sub5 does to sub1).
* sub9 sets the global `gVEHCounter1` to a random value < 4096 (this is later counted down by main function).
* sub10 only rehashes the region, but doesn't change any other globals. It is not called at all if sub4 set its state to logical zero.

After all these functions were called enough times (and so returned true), the main function verifies that `gVEHState1` is set to whatever value sub5 should have set it to (and crashes if that's not correct).
Then it starts calling sub11 until it was called enough (before that, it sets `gVEHCounter2` to another random value). And then it does another check (whether kernel debugger is enabled) and crashes on failure.

At this point it checks whether another global is non-zero. So far we haven't seen a code that initializes it - this is done later by code in TLS callback. Until it's non-zero, it simply sometimes rehashes the bootstrap region and returns.

After that global is initialized, it counts down `gVEHCounter2` times (set by sub11). Then it verifies that `gVEHState2` is set to expected value by sub8 (crashes if not), depending on `gVEHState4` calls another function sub12 (this one is similar to sub3, does nothing interesting).
Checks for hardware breakpoints again (crashes if found), does another pointless function sub13 (similar to sub3), and finally it calls the only important function `sub14` in the whole story.
After it's done, it does another countdown for `gVEHCounter1` (set by sub9), and from that point keeps calling yet another pointless function sub15 (similar to sub3).

TLDR of all this - this is a whole bunch of junk that does some anti-tampering checks (rehashing bootstrap code periodically, presumably to detect usual int3 breakpoints, checking hardware breakpoints and kernel debugger's presence).
The only important function in all this is `sub14`. It can't be called until normal TLS code initializes a particular global, so let's come back to that later once we understand what it is.

### Back to TLS

Now that we're back to the normal code, `setup_veh` has returned true, every single instruction we execute triggers VEH doing it's silly shit (damn this must be so inefficient... poor CPU).
The only problem we need to deal with is - there are now a bunch of `hlt` instructions in the code (these kick the VEH to restart if it reaches the invocation limit and disables itself), and IDA considers them to be noreturn.
It's easy enough to fix in disassembly (by manually adding flow xref to next instruction), but I don't know how to fix it in hexrays. Thankfully, they are not particularly important (until we reach `wbinvd`), so I just nop them out as I see them.

The next piece of code does some decryption. This is a recurring pattern that we'll see a lot in the future.
First, it initializes the scratch buffer (`char[256]`) so that `scratch[i] == i`. Then it shuffles it around, using some global memory block to guide it (find the next index to swap). Finally, it uses it to decrypt some data (this time it's a 12-byte structure).

The decrypted structure is then checked for tampering (first dword is compared to FNV hash of the rest), and then assuming it's all good some function is called. Let's look at this function.
First it has some familiar obfuscation I've seen already, where it takes a few algorithm-parameter pairs as arguments and emits a bunch of code that ends up being identity transformation - this can just be ignored.
Then it goes through all loaded modules, takes the substring of their names (prefix/suffix/full name, depending on structure, of a length depending on a structure), and compares to the hash stored in an input structure.
So it's clear: this function is `bool any_module_loaded(ModuleEntry* entries, int numEntries, ...obfuscationPairs)`. The `ModuleEntry` is `uint hash; ushort len; bool prefix; bool suffix;`.
The TLS callback then passes the decrypted data as single module entry - and if the matching module is loaded (or if the buffer was tampered with), the function returns immediately.
So this is some 'blacklist' for loaded dlls, since I only know the hash, I have no clue what this forbidden module is :)

The next thing TLS callback does is decrypt in-place some large (size 0x398) structure in data section - let's call it `gBootstrapInfo` and define a `BootstrapInfo` structure to match it.

Next step is calling `VirtualAlloc` (it was found by `setup_veh` before) to allocate a chunk of memory. The size is `0xE88 + 0x30 * (NumSectionsInExecutableImage + 1) + size of some function`. The allocated memory is then immediately filled with random bytes.
This pointer is later assigned to a global that - by cross-referencing dump - I know to be the pointing to `AntidebugState` - so we know what the first `0xE88` bytes are.
There's also an early-out if `BeingDebugged` flag is set in PEB in the middle of this.

Then it calls `NtCreateSection` of the size equal to the executable image size and with `SEC_NO_CHANGE` flag - ok this looks like the start of the remapping code, I've learned about it way at the beginning of this investigation.
Next is `MapViewOfFileEx`, followed by `VirtualProtect` marking the entire image as `PAGE_EXECUTE_READWRITE` and copy of the entire image into the new mapping. Next is copy of a subset `gBootstrapInfo` and finding first zero entry.
Since this is probably related to remapping, let's call this substructure `SectionRemapInfo`, it has three dwords, and there is an array of 32 such structures in `BootstrapInfo` at offset 8.

Finally, some function is copied to the end of the block allocated by `VirtualAlloc` before, and then VEH is stopped by executing `wbinvd`. This looks like preparing to unmap original executable and something with the sections, so let's call the function `remap_sections`.

### Phase M

At this point the TLS function sets phase tag to `M` and calls the copy of `remap_sections`. The function is simple, it accepts a single pointer, so let's define an args structure, define all fields that are accessed in the function, and then go back to TLS to see how they are filled:
```
struct RemapSectionsArg {
	/* 0x00 */ void* xorredImagebase; // original, where loader mapped the exe
	/* 0x08 */ void* xorredSectionHandle;
	/* 0x10 */ void* xorredSectionMapping; // where we're remapping exe to
	/* 0x18 */ SectionRemapInfo* xorredSectionInfo;
	/* 0x20 */ uint xorredNumSections;
	/* 0x28 */ void* xorredUnmapViewOfFile;
	/* 0x30 */ void* xorredMapViewOfFileEx;
}
```
Every field is xorred with some constant, which can be seen either in TLS or in remap functions. The function itself is very simple - it calls `UnmapViewOfFile` on the imagebase and then `MapViewOfFileEx` to map each section in `sectionInfo` individually, at the same address.

After remapping is done, another `hlt` instruction restarts VEH. At this point, each section is mapped into two places - at the original address that loader selected, and at whatever address was assigned by first `MapViewOfFileEx`.

TLS function then records start and size of three sections; two from `gBootstrapInfo` (last four fields) - corresponding to .text and .data sections of the exe, and third same as .text, unless executable is not the first loaded module (not sure what this all means).
The corresponding fields in bootstrap info are then overwritten with random values.

Finally TLS function stores the original section mapping in a global that is checked by VEH handler - this unblocks the rest of the VEH logic. TLS function then starts looping doing pointless operations until some global is initialized (presumably, by VEH).
Before going back to VEH, a quick look into the code after the loop ends shows a familiar obfuscation pattern - two constants are saved in variables, then a function is called with their addresses.
Cross-checking RVAs - it's indeed the familiar `antidebug_obfuscate` function - however, it's decrypted for now. The hypothesis then is that VEH decrypts it and sets this global once it's ready - let's verify it.

### The rest of the VEH handler

Now `bootstrap_veh_sub14` can finally run. This follows the familiar pattern of the VEH subfunctions, but the logic it executes when specific invocation count is reached is interesting.

It starts by reading `KUSER_SHARED_DATA.NumberOfPhysicalPages`, hashing it, then copying 1024 byte region from a buffer that depends on `hash & 0xF` into a local. Then it does some decryption loops.
Finally, it does some 'makeshift relocations' - looks for specific hardcoded values in the decoded output and replaces them with code section start/end/size - and writes the result back into the mapped section, right where `antidebug_obfuscate` is.
After that is done, it sets the global that the TLS is now waiting for.

The last important thing it does before returning is calculates the hash of the decrypted buffer, obfuscates it using now-decoded `antidebug_obfuscate`, and stores it in a global `gObfuscateHash`.
It then obfuscates a constant zero with some other arguments and stores in another global `gObfuscatedZero`.

So this seems to be this 'machine-specific' part of the obfuscation process - there are 16 different variants of the `antidebug_obfuscate`, and whatever is selected depends on machine properties (num physical pages).
I've made a simple script to decode all variants and save them into a file, and then loaded this file into idb - all these functions are conceptually similar, but use slightly different operations and values.
They also all contain a return-address check and crash if called from code outside executable image - and because they are hashed, there's probably some function somewhere that checks it for tampering (although I haven't seen it).
All of them are symmetric, so the encryption/decryption is identical. Apparently I've observed variant 9.

And that is the only important thing that VEH does, the rest is usual crap.

### Back to TLS, again

As soon as the `antidebug_obfuscate` is decrypted, TLS function continues - and next thing it does is use it to initialize a bunch of `AntidebugState` fields:
* 0x750 to imagebase of kernel32.dll
* 0x0F8 to page hash table (a block of VirtualAlloc'd memory, sized to contain qword per page fitting into `SizeOfImage`) and 0x100 to the number of qwords in the page hash table
* 0x050 to imagebase of the executable
* 0x188 to the address of the first section mapping
* 0x2A3 to whether first module in loader's module table is not the executable (a bool)
* 0x2F0 to the loader's entry corresponding to ntdll.dll

It then calls another function (let's call it `init_antidebug_state`) to initialize the page hash table with obfuscated zeros and fill out more fields in `AntidebugState`.
Finally, it stops VEH by executing `wbinvd` and finally removing it completely by `RtlRemoveVectoredExceptionHandler`.

### Phase F

The next part starts by setting phase tag to `F`, and it deals with imports. First, it calls a function I'll call `get_kernel32_apis`, which just uses now-familiar manual lookup to find things next part will need - specifically, `LoadLibraryA`, `GetProcAddress` and `VirtualAlloc`.
Then it reads the PE header for Import and IAT directory entries, decrypts the import directory's size field (which actually contains RVA of the encrypted import table, apparently that doesn't break the loader, huh), and calls a `decrypt_imports` function.

The encrypted import table is just a zero-dword-terminated array of encrypted `IMAGE_IMPORT_DESCRIPTOR` structures - so the function simply decrypts each entry, decrypts the name of the library and calls `LoadLibraryA`.
Then there's a piece of code that does something special for libraries with `msvc` string (there are none in the executable). Finally, it loops through the imported function list for the library, decrypts each function name (unless import is by ordinal), and calls `GetProcAddress`.

The only slightly interesting part is how it builds an import thunk. First, it allocates a page to store them. Then, as an extra layer of obfuscation, it generates a random (5 to 14) number of random adjustments (add/sub/xor) to the address, split into chunks of 1-5 operations.
Then it tries to fit each chunk in a page, first by trying a random offset up to 7 times, then by brute-force methodically trying every single offset. If it can't find a spot, or if the current page is 50%+ full already, it allocates a new page.
Finally, once the spot for the chunk is found, it emits the instructions (initial `mov rax, ...`, a sequence of add/sub/xor that eventually turns rax into the desired address, and finally a `jmp rax`).

All in all, this looks like a pretty pointless obfuscation - hexrays automatically does this maths and shows the correct call in decompilation output.

### Phase D

Finally, the most interesting part starts, identified by phase tag `D`. The `BootstrapInfo` contains an array of 32 (rva, size) pairs starting at offset 0x188 - these are the encrypted regions of the binary (in practice, executable only has one entry there, which is the entire text section).

The function then goes through each page of each region and, unless it's within the area containing bootstrap code, calls one of the three versions of the decryption functions. Since the executable has only one region, only first of these variants seems to ever be used.
Even then, they seem to be functionally identical (unless there are some minor differences I didn't spot). So let's focus on the first variant - `decode_page_var0`.

The function starts with familiar algorithm-parameter adjustment pairs (hilariously, it 'obfuscates' the magic constants in DOS & PE headers - probably their encryptor just picks first constants used by the function).
Then it verifies whether first the first byte in the pagehash entry is still not set and early-outs if it is; the function also sets this to 1 at the exit, implying that this field is `bool decrypted`.

Assuming the page still needs to be decrypted, the function then goes through all relocations intersecting the page and undoes them.
This is understandable - the loader fucked up the encryption by applying the relocations - although I wonder, why doesn't the encryptor just remove them from the native relocation table?..

The last remaining tricky bit is relocations straddling page boundary (remember the very beginning of phase I saving them in a global array) - the encrypted page bounds are adjusted so that full address is in the single block:
if relocation straddles boundary between page N and N+1, the full address is encrypted as part of block N.

At this point everything is ready, and the page is decrypted using familiar shuffling algorithm. As an extra layer, previous page's FNV hash is included into the algorithm for decrypting next page (and after decryption, just-decrypted-page is hashed).
The relocations are reapplied after decryption is done.

Finally, the decrypted page is hashed again using other algorithm and hash is recorded in page hash table - in other words, page hash table entry is set if and only if the page is encrypted in executable.

### Finishing touches after all pages are decrypted

TODO: hiding main thread from debugger, segment states + hashing page containing it, secondary mapping setup, clobbering headers

### Phase C

TODO: post-decrypt TLS callback, patching entry point
