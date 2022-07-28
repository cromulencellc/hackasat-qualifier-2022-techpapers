# Blazin' Etudes - Hack A Sat 3 Quals (2022) - Writeup

Author: chainsaw10

(If you just want the solution, and not the story, skip down to "Emulating MLIL
on z3")

## Introduction

This year was Samurai's third time playing Hack A Sat's (HAS) quals round. The
first time we played, we qualified for finals. Year 2, we didn't qualify. So
this year we were hoping to qualify again. I personally wasn't super involved in
the first year, and only a bit involved last year (I don't think the weekends
lined up super great for me), but I was interested to take a shot at it this
year and hopefully qualify!

Blazin' Etudes was the third of a series of microblaze reversing challenges,
released on the last day of the competition (Sunday). In order to properly
appreciate it, we should briefly look at the preceding challenges.

I woke up Saturday morning a few hours after the start of the competition. I
looked at Samurai's chat and saw the competition was well underway. I started to
sleepily survey the categories and saw there was an oddball architecture
challenge. Months ago, I had read in Binary Ninja's public Slack about someone
building a Binary Ninja architecture plugin for this random arch called
microblaze, so its existence was vaguely familiar. I decided to take a look.

The first challenge was called Small Hashes Anyways, and everyone was busy
taking stock of what we had to work with. Ideas flew for different ways to
disassemble and run the challenge binary. Before I finished waking up and
getting up to speed, one of my sharp teammates had already solved it. It sounds
like an educated bruteforce was the quickest win.

## Ominous Etude
We moved onto the next challenge, called Ominous Etude. I was now vaguely awake
and at my computer, so I installed the plugin for Binary Ninja and opened up the
challenge binary. I noticed there appeared to be a bug computing call targets.

```
100032d8  int32_t main()
100032f8      0xfffdf5c(0x101e15e8, 0xffff9df0)    // hmmm this call doesn't look right
10003314      std::istream::operator>>(&std::cin)
10003344      uint32_t var_8
10003344      if (zx.d(quick_maths(var_8) ^ 1) != 0)
10003370          0xfffc2e4(0xfffdf5c(0x101e15e8, 0xffff9e08), 0xffffd5f0)
10003380          exit(1, 0xffffd5f0)
100033b4      0xfffc2e4(0xfffdf5c(0x101e15e8, 0xffff9e1c), 0xffffd5f0)
100033c4      exit(0, 0xffffd5f0)
100033c4      return __static_initialization_and_destruction_0(0, 0xffffd5f0) __tailcall
```

We chatted about it a bit in Discord voice, and we dug up the [microblaze arch
spec](http://www.cs.columbia.edu/~sedwards/classes/2005/emsys-summer/mb_ref_guide.pdf)
to learn how call instructions (er `brlid` instructions) work on this
architecture. While some of us dove down the Binary Ninja rabbit hole, others
were trying out r2, Ghidra, and IDA plugins. One teammate using the IDA plugin
hand-decompiled the `quick_maths` function and brute-forced the solution, which
gave us the flag. Total time to solve: roughly an hour and a half.

## Debugging the Binary Ninja plugin

At this point, I figured that if there had been 2 microblaze challenges already,
there might be more (plus I like goofing around with tooling), so I wanted to
finish fixing the plugin. A couple teammates joined me on this expedition.

We compared the IDA disassembly with the Binary Ninja disassembly and noticed
that there seemed to be a problem computing the immediates. We noticed the sign
bit was set on the immediate section of the `brlid` instructions that were
incorrect.

```
> chainsaw10: I'm going to abuse this as a chat about the microblaze stuff for lack of another channel  
> chainsaw10: `wrong: b0000009b9f4ac60  correct: b0000007b9f438ec`  
> chainsaw10: so the one on the left ends up wrong, the one on the right shows up correct  
> chainsaw10: I wonder if they're incorrectly sign extending
```

Microblaze nominally has 32-bit instructions, which only really leaves room for
a 16-bit immediate value. However, they want to allow full 32-bit immediates for
certain instructions, like `brlid`, so they have a prefix instruction, `imm`,
which adds another 16-bits worth of immediate.

It turned out that the plugin was unconditionally sign extending the 16-bit
immediate in these instructions. There was a check elsewhere for the `imm`
prefix, but there was no code to un-sign-extend the lower 16 bits. (An easy
enough bug to write, no disrespect intended to the plugin author!)

```python
@bitspec.dataclass('-:16 i:s16')
class Rel16(Imm16):
    """Imm16 operand statically known to be relative address pointer.
```

```python
            if isinstance(y.b, microblaze.Imm16):
                y = copy.copy(y)  # ???
                y.b = microblaze.Imm32(
                    i=(x.b.i << 16) | (y.b.i),
                    fused_from=type(y.b)
                )
```

> Do all sufficiently complex binary analysis projects really contain an ad-hoc implementation of LLVM's MCInst?  
> &mdash; amtal, https://amtal.github.io/bitspec/#motivation-and-similar-tools


Ok, great, we just need to fix up that math and we'll be golden. However, to
somewhat misquote amtal, the plugin author, all Binary Ninja arch plugins
contain an ad-hoc domain-specific language for writing disassemblers and
lifters. To implement a robust solution, we'll need to spend a few minutes
finding the right place to fix it.

amtal had created and used a library called `bitspec` to handle the bit math and
pattern matching needed to write the disassembler. At a quick glance, it looks
really cool, and it seems like a great approach! However, on a CTF time-scale,
we did not want to learn how this library worked, so we looked for some normal
Python code away from any decorator magic :) . My teammate and I bounced ideas
back and forth and eventually settled on creating a new `Rel32` class to hold
some of our hackery. We then adjusted the `imm` instruction handler to use it.

```diff
diff --git a/arch.py b/arch.py
index 664c197..c5eebe3 100644
--- a/arch.py
+++ b/arch.py
@@ -143,10 +143,21 @@ def fuse_ops(data, addr, order):
         else:
             if not (y:= next(ops, None)):
                 return  # not enough data to disambiguate
-            if isinstance(y.b, microblaze.Imm16):
+            if isinstance(y.b, microblaze.Rel16):
+                y = copy.copy(y)  # ???
+                y.b = microblaze.Rel32(
+                    i=(x.b.i << 16) | (y.b.i & 0xFFFF),
+                    #fused_from=type(y.b)
+                )
+                # length is treated as 8 to fool assembler algorithm, but .addr
+                # is still the non-IMM instruction's addr so lifter/branch
+                # predictor should still be correct
+                y.__bitspec_match__ = FusedLength
+                assert len(y) == 8
+            elif isinstance(y.b, microblaze.Imm16):
                 y = copy.copy(y)  # ???
                 y.b = microblaze.Imm32(
-                    i=(x.b.i << 16) | (y.b.i),
+                    i=(x.b.i << 16) | (y.b.i & 0xFFFF),
                     fused_from=type(y.b)
                 )
                 # length is treated as 8 to fool assembler algorithm, but .addr
diff --git a/microblaze.py b/microblaze.py
index e2b45e3..b3a441d 100644
--- a/microblaze.py
+++ b/microblaze.py
@@ -41,12 +41,25 @@ class Rel16(Imm16):
         ea = (self.i + addr) & 0xFFFFffff
         return [
             tok(ty.PossibleAddressToken, hex(ea), ea),
-            tok(ty.TextToken, ' - '),  # do not break il.Operand count
-            tok(ty.PossibleAddressToken, hex(addr), addr),
         ]
     def r(self, il, addr=None, sz=4): 
         return il.const_pointer(sz, (self.i+addr) & 0xFFFFffff)
 
+class Rel32(Rel16):
+    def __init__(self, i):
+        self.i = i
+    def ea(self, addr):
+        # TODO: figure out if this wraps properly
+        return (self.i + addr) & 0xffffffff
+    def text(self, addr):
+        tok, ty = bn.InstructionTextToken, bn.InstructionTextTokenType
+        ea = self.ea(addr)
+        return [
+            tok(ty.PossibleAddressToken, hex(ea), ea)
+        ]
+    def r(self, il, addr=None, sz=4):
+        return il.const_pointer(sz, self.ea(addr))
+
 @bitspec.dataclass('-:16 i:s16')
 class Abs16(Imm16):
     """Imm16 operand statically known to be absolute address pointer.
```

```
100032d8  int32_t main()

100032f8      std::operator<<<std::char_traits<char> >(&std::cout, "enter decimal number: ")
10003314      std::istream::operator>>(&std::cin)
10003344      uint32_t var_8
10003344      if (zx.d(quick_maths(var_8) ^ 1) != 0)
10003370          std::ostream::operator<<(std::operator<<<std::char_traits<char> >(&std::cout, &data_10199e08))
10003380          exit(1, 0x1009d5f0)
100033b4      std::ostream::operator<<(std::operator<<<std::char_traits<char> >(&std::cout, "cool :)"))
100033c4      exit(0, 0x1009d5f0)
100033c4      return __static_initialization_and_destruction_0(0, 0x1009d5f0) __tailcall
```

This was enough to clean up our decompilation of `main`, as well as of
`quick_maths`. At this point, another teammate dropped in chat to let us know
that the next reversing challenge wasn't microblaze, and it might not be worth
devoting any more time to fixing up this plugin.

So naturally, I ignored his perfectly good advice and spent another 15 minutes
staring at it to make sure the fix was robust. (I swear, I really was going to
move on after that!) It turned out the fix wasn't robust -- the same issue
applied to instructions that loaded 32-bit absolute integers, rather than just
IP-relative integers. I applied the fix you see above, `(y.b.i & 0xFFFF)`, then
moved on to other challenges.

```
> chainsaw10: Now I'm done screwing around with binja unless we find more arch bugs
```

## Blazin' Etudes

It would, in fact, have been a waste of CTF time, if not for the next challenge.
In hindsight, "ominous" coupled with the simplistic design of this challenge
binary should probably have been a clue, but I missed it at the time.

However, about a day later, a new microblaze challenge dropped, Blazin' Etudes.
In the style of the 334, 666, and 1000 cuts challenges from Defcon CTF 2016
quals, we were provided 178 nearly identical binaries, with just the constants
changing. The remote service would prompt us with the name of the binary, and we
needed to provide a valid input for it.

Now, back in 2016, I was still in college. I was too chicken to attempt Quals
that year, but I remember hearing from one of my friends about this challenge,
and I had eagerly read [Ryan Stortz's 2000 cuts with Binary
Ninja](https://blog.trailofbits.com/2016/06/03/2000-cuts-with-binary-ninja/)
blog post. As an undergrad, actually buying an IDA license was out of reach, so
news of an up-and-coming competitor that was actually good was excellent news. I
dreamed of one day doing something similar to that blog post. Well, fast forward
6 years and now I have my chance, or something like that. 

```
> chainsaw10: I'm planning to attempt scripting binja  
> chainsaw10: Just trying to figure out an automated way to solve the quick_maths  
> chainsaw10: Current plan is to write an MLIL emulator in terms of z3 then solve  
> chainsaw10: I think I can do that somewhat quickly  
```

## Binary Ninja

Based on the theory behind the 2000 cuts blog post, I was planning to leverage
Binary Ninja's intermediate languages to abstract away the Microblaze
architecture (that I didn't know anything about before today). Binary Ninja is
a disassembler, similar to IDA and Ghidra, with a focus on having a usable API.
The authors take inspiration from the construction of compilers. Compilers start
by parsing your code into an AST, which they then "lower" to some intermediate
representation (IR) (of which the most famous is LLVM IR). Often, compilers will
then perform simplifying (or "lowering") passes upon their IR until they
eventually reach a representation that maps onto machine code, at which point
they can do code generation.

In the same vein, Binary Ninja starts at the bottom and works up. It starts by
"lifting" from assembly to a machine-independent representation they call
"Lifted IL" (where IL is "intermediate language", a synonym for "intermediate
representation"). Then they perform analysis and abstract away CPU flags, which
yields "Low Level IL", or LLIL. Next, stack analysis is performed and registers
and stack are combined to form "variables". Calling conventions are analyzed and
function calls are annotated with their full argument list. This, combined with
some analysis I've likely left out, forms "Medium Level IL" (MLIL). To reach a
state most would agree is "decompilation", they next analyze control flow and
recover if-statements and high level loops. Variables are deduplicated.
Eventually, they reach "High Level IL" (HLIL), which maps directly to C
constructs. They've fully inverted a compiler's pipeline, replacing lowering
passes with lifting passes.

Not mentioned in that summary is all the dataflow and value-set analysis that
enables you to point at a variable and ask Binary Ninja what its value is.
Additionally, Binary Ninja can optionally give you any of that set of ILs in
Static Single Assignment (SSA) form, where each time a variable is modified, it
is given a new name. This aids your analysis as each value in the analyzed
function has a name. Recovering SSA form from normal use of variables is a
somewhat mechanical process (summarized first in a paper by [Cytron et
al](https://dl.acm.org/doi/pdf/10.1145/115372.115320)), but having tried to code
it up myself previously, I can attest that it's tedious and I'd much prefer lean
on Binary Ninja to do that for me.

## Alright how is all this fancy program analysis going to help me win

So at this point we have our pick of the different levels of (de?) optimization
from Binary Ninja. I chose MLIL in SSA form because it's often recommended as
best for analysis, and I happen to understand it the best. Here's a snippet of
how the `quick_maths` function displays in the UI. We can see a set of
consecutive math operations ending in a return statement. Our analysis is
simplified by the fact that the entire function is one basic block (i.e. no
conditionals).

```
10000964  uint32_t quick_maths(int32_t arg1)

   0 @ 10000974  arg_4#1 = arg1#0
   1 @ 10000978  r3#1 = arg_4#1
   2 @ 1000097c  r3_1#2 = r3#1 - 0x29
   3 @ 10000980  arg_4#2 = r3_1#2
   4 @ 10000984  r3_2#3 = arg_4#2
   5 @ 10000988  r3_3#4 = r3_2#3 - 0x6a
   6 @ 1000098c  arg_4#3 = r3_3#4
   7 @ 10000990  r3_4#5 = arg_4#3
<...snip>
  88 @ 10000af4  r4_28#29 = r4_27#28 << 1
  89 @ 10000af8  r4_29#30 = r4_28#29 << 1
  90 @ 10000afc  r4_30#31 = r4_29#30 << 1
  91 @ 10000b00  r4_31#32 = r4_30#31 << 1
  92 @ 10000b04  r4_32#33 = (r4_31#32 << 1).b
  93 @ 10000b08  r3_41#42 = r4_32#33
  94 @ 10000b0c  r3_42#43 = zx.d(r3_41#42)
  95 @ 10000b20  return r3_42#43
```

Next, I must introduce another favorite CTF tool, z3! z3 is the product of years
of research at Microsoft Research, with a goal of solving SAT problems as
efficiently as possible.  For CTF purposes, it turns out that it's really good
at algebra. The Python bindings for z3 allow us to declare variables and use
normal overloaded operators to build an expression. We can then declare
constraints with the expression and ask z3 for values of our variables that
satisfy those constraints. I've included a simple example below:

```python
>>> import z3
>>> s = z3.Solver()
>>> x = z3.BitVec("x", 32)
>>> y = z3.BitVec("y", 32)
>>> s.add(y-x == 42)
>>> s.add(x-3 == 7)
>>> s.check()
sat
>>> s.model()
[x = 10, y = 52]
```

So now in theory we have a plan. We'll loop through the `quick_maths` function
and compute a z3 expression for each SSA variable assignment. (Here we make use
of the fact that each variable only has one assignment!) Once finished, we tell
z3 that the return value is equal to 1 and ask it to solve. It should quickly
find the input value to satisfy that constraint.

## Emulating MLIL on z3

```
11 @ 100009a0  r3_7#8 = r3_6#7 + 0x225
```

Binary Ninja's ILs follow a tree-based format. That instruction above is a
`MLIL_SET_VAR_SSA` instruction, where the "dest" is an `SSAVariable`, and the
`src` is itself a `MLIL_ADD` expression, with a `left` side of `MLIL_VAR_SSA`
and a `right` side of `MLIL_CONST`.

Writing a series of consecutive conditionals to handle all those possibilities
can be daunting, unless we reach into the annals of object-oriented design and
take inspiration from the [Visitor
pattern](https://github.com/trailofbits/binjascripts/blob/master/find_heartbleed/bnilvisitor.py).
As it applies here, we can write roughly the following pseudocode:

```typescript
function emulate(insn: Instruction): Expression {
    switch (insn.op) {
        case MLIL_SET_VAR_SSA:
            add_constraint(insn.dest == emulate(insn.src))
        case MLIL_ADD:
            return emulate(insn.left) + emulate(insn.right)
        case MLIL_VAR_SSA:
            return generate_varname(insn.src)
        default:
            print("you didn't emulate", insn)
    }
}
```

This neatly takes care of the tree-walking for us via recursion! At the end we
can implement `case MLIL_RET` to ask z3 for the solution.

So I did this. And I ended up with Python that looked roughly like the
following (note the full solve script is available at the bottom):

```python
class Emulator:
    @staticmethod
    def z3var_from_ssa(ssa_var, size):
        assert size in [1, 4]
        return z3.BitVec(ssa_var.name + "#" + str(ssa_var.version), size*8)

    def emulate(self, insn):
        if isinstance(insn, bn.SetVar):
            var = self.z3var_from_ssa(insn.dest, insn.size)
            expr = self.emulate(insn.src)
            self.s.add(var == expr)
        elif isinstance(insn, bn.MediumLevelILVarSsa):
            return self.z3var_from_ssa(insn.src, insn.size)
        elif isinstance(insn, bn.MediumLevelILAdd):
            return self.emulate(insn.left) + self.emulate(insn.right)
        elif isinstance(insn, bn.MediumLevelILSub):
            return self.emulate(insn.left) - self.emulate(insn.right)
        elif isinstance(insn, bn.Return):
            retval = self.emulate(insn.src[0])
            self.s.add(retval == 1)
            return retval
        else:
            print("unhandled", insn.operation)

    def solve_for_arg(self, mlil_bb):
        retval = None
        for insn in mlil_bb:
            retval = self.emulate(insn)
        print(self.s)
        chk = self.s.check()
        print(chk)
        if chk == z3.sat:
            res = self.s.model()[z3.BitVec("arg1#0", 4*8)]
            return res

```

And I ran it and I got... `unsat`, z3's way of saying "that's impossible".

```
> chainsaw10: I have a vaguely working emulator, but I'm getting unsat
> chainsaw10: so should just need to debug
```

What could I possibly have wrong? Well, there are lots of options:

1. Microblaze is big-endian. It's possible I have endianness somehow wrong, or
   maybe the architecture plugin's lifting does.
2. Maybe I'm not properly handling integer overflow or bit math or something.
   (z3's BitVec type is designed for precisely this, but maybe I'm holding it
   wrong.)
3. Maybe my bitshift emulation is wrong. IDK how z3 numbers bits, maybe
   something's switched somewhere. The shift operation isn't "shift", it's 
   "extract bits".

So what can you do? Well, I tried weakening the constraint on the return value.
Eventually I tried just setting it non-zero, and that got me `sat`!

```
> chainsaw10: I have a solve that works for _most_ but not all binaries
```

So I coded up a harness to talk to the remote and throw solutions, let's see
what happens. Along the way it turns out pwntools doesn't play nicely on an M1
Mac, so I tried out [`mpwn`](https://github.com/lunixbochs/mpwn), which worked
well.

```
> chainsaw10: I've gotten as many as 7 in a row, but that's not enough
> teammate: show me your script
```

It was kinda fun watching my script solve a few binaries (before hitting one
that hit our bug and failing), so I reran it a few more times for the fun of it.
But one time I didn't get an error. I looked closer, and I had gotten lucky and
gotten 10 binaries in a row that didn't use whatever operation was buggy in my
emulator! But I hadn't handled the "win" case in my script, so it just exited. 

```
> chainsaw10: hell, I should just run it again. It just won, but I didn't print the flag
> chainsaw10: It only won once in like 30
> chainsaw10: but that's doable
```

So I fixed the bug (ensuring I used `r.interactive()` to drop to an interactive
shell if I won but didn't read the flag properly in my script) and reran it. And
reran it, and reran it, like 15 times. Finally on what had to have been the 20th
time, I got lucky and it gave me the flag. Time to solve: ~2 hours.

## Epilogue

So what was the bug? 

```
10000a8c  90830041     srl r4, r3
10000a90  90840041     srl r4, r4
10000a94  90840041     srl r4, r4
10000a98  90840041     srl r4, r4
10000a9c  90840041     srl r4, r4
10000aa0  90840041     srl r4, r4
```

Well, it turns out that `srl` is a shift left, not a shift right, as it was
lifted to be. I had noticed it seemed off, and I tried to correct for it, but I
apparently had something else messed up, and in the confusion I never properly
tested it.

Incidentally, from talking to someone from another team in the Hack-A-Sat Slack
afterward, I realized that my goofing around on Saturday had saved me a good bit
of trouble.  The bug in the 32-bit immediates affected `xor` instructions.
Trying to debug subtly-wrong `xor` immediate values would have been very
difficult.

After the competition, I [submitted a
PR](https://github.com/amtal/microblaze/pull/2) to fix the bugs we found, and it
was accepted soon after. I don't mean to complain about the bugs, as the plugin
seems pretty good overall, and I can easily imagine writing those bugs myself.
Not to mention that they made for a more interesting time playing the CTF, and a
far more fun writeup.

(A lightly copyedited version of this writeup will eventually appear on my
website.)

## Solve script

```python
from mp import *
import base64
import glob
import sys
import z3
import binaryninja as bn

FUNCNAME = '_Z11quick_mathsj'

class Emulator:
    def __init__(self, bv):
        self.s = z3.Solver()
        self.hooks = {
                self.get_import(bv, "__udivsi3"): self.hook_udivsi3,
        }

    def hook_udivsi3(self, insn):
        lhs = self.emulate(insn.params[0])
        rhs = self.emulate(insn.params[1])
        #return lhs / rhs
        return z3.UDiv(lhs, rhs)

    @staticmethod
    def get_import(bv, name):
        type = bn.SymbolType.ImportedFunctionSymbol
        try:
            sym = next((sym for sym in bv.symbols[name] if sym.type == type), None)
        except KeyError:
            sym = None
        if not sym:
            return None
        return sym.address

    @staticmethod
    def z3var_from_ssa(ssa_var, size):
        assert size in [1, 4]
        return z3.BitVec(ssa_var.name + "#" + str(ssa_var.version), size*8)

    def emulate(self, insn):
        if isinstance(insn, bn.SetVar):
            var = self.z3var_from_ssa(insn.dest, insn.size)
            expr = self.emulate(insn.src)
            self.s.add(var == expr)
        elif isinstance(insn, bn.Call):
            assert insn.dest.operation == bn.MediumLevelILOperation.MLIL_CONST_PTR
            addr = insn.dest.constant
            result = self.hooks[addr](insn)
            output = self.z3var_from_ssa(insn.output[0], insn.dest.size)
            self.s.add(output == result)
        elif isinstance(insn, bn.MediumLevelILVarSsa):
            return self.z3var_from_ssa(insn.src, insn.size)
        elif isinstance(insn, bn.MediumLevelILAdd):
            return self.emulate(insn.left) + self.emulate(insn.right)
        elif isinstance(insn, bn.MediumLevelILSub):
            return self.emulate(insn.left) - self.emulate(insn.right)
        elif isinstance(insn, bn.MediumLevelILXor):
            return self.emulate(insn.left) ^ self.emulate(insn.right)
        elif isinstance(insn, bn.MediumLevelILLsl):
            # Work around arch plugin bug if not using fixed plugin
            return z3.LShR(self.emulate(insn.left), self.emulate(insn.right))
        elif isinstance(insn, bn.MediumLevelILLsr):
            return z3.LShR(self.emulate(insn.left), self.emulate(insn.right))
        elif isinstance(insn, bn.MediumLevelILOr):
            return self.emulate(insn.left) | self.emulate(insn.right)
        elif isinstance(insn, bn.MediumLevelILZx):
            assert insn.size == 4 and insn.src.size == 1
            return z3.ZeroExt(32-8, self.emulate(insn.src))
        elif isinstance(insn, bn.MediumLevelILLowPart):
            assert insn.size == 1 and insn.src.size == 4
            src = self.emulate(insn.src)
            return z3.Extract(7, 0, src)
        elif isinstance(insn, bn.Constant):
            return insn.constant
        elif isinstance(insn, bn.Return):
            retval = self.emulate(insn.src[0])
            self.s.add(retval == 1)
            return retval
        else:
            print("unhandled", insn.operation)

    def solve_for_arg(self, mlil_bb):
        retval = None
        for insn in mlil_bb:
            retval = self.emulate(insn)
        print(self.s)
        chk = self.s.check()
        print(chk)
        if chk == z3.sat:
            res = self.s.model()[z3.BitVec("arg1#0", 4*8)]
            return res

def handle_bin(bv: bn.BinaryView):
    syms = bv.symbols[FUNCNAME]
    assert len(syms) == 1
    func = bv.get_function_at(syms[0].address)
    assert func
    mlil = func.mlil.ssa_form
    assert len(list(mlil)) == 1 # one basic block
    mlil_bb = list(mlil)[0]
    emu = Emulator(bv)
    res = emu.solve_for_arg(mlil_bb)
    if res is not None:
        return base64.b64encode(str(res).encode()).decode()

def handle_filename(filename):
    filename = "/Users/zack/Downloads/blazing_etudes/" + filename
    with bn.open_view(filename) as bv:
        return handle_bin(bv)

TICKET = "<ticket>"

if sys.argv[1] == "TEST":
    successes = 0
    for file in glob.glob("/Users/zack/Downloads/blazing_etudes/*"):
        with bn.open_view(file) as bv:
            if handle_bin(bv) is not None:
                successes += 1
            else:
                raise Exception("bug: " + file)
    print("Test finished with", successes, "successes")

elif sys.argv[1] != "REMOTE":
    with bn.open_view("/Users/zack/Downloads/blazing_etudes/alarming_shuffle") as bv:
        print(handle_bin(bv))
else:
    r = remote("blazin_etudes.satellitesabove.me", 5300)
    r.expect("Ticket please:\n")
    r.sendline(TICKET)
    r.expect("followed by a newline\n")
    wins = 0
    while True:
        data = r.recvline()
        print(data)
        if b"You did it" in data:
            print(r.recvline())
            r.interactive()
        elif b"didn't exit happy" in data.lower():
            wins -= 1
            break
        name, sha = data.strip().split()
        assert b"." not in name and b"/" not in name
        result = handle_filename(name.decode())
        if result is not None:
            wins += 1
            r.sendline(result)
        else:
            print("Failed to solve for", name.decode())
            break
    print("Number of wins", wins)
    r.close()
```