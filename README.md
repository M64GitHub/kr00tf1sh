# kr00tf1sh
linux desktop (KDE) root-access security breach (2007) suggesting ptrace_scope like solution into the kernel.

Proof of concept code that is/was able to:
 - steal the entered password out of memory from the kdesu process
 - secretly execute other commands than the user wanted, then performing the users task
 -   -> open the way for malware to gain root access due to desktop insecurity by design

(see kr00tf1sh.c for the final code)

See [gist](https://gist.github.com/M64GitHub/5353d9cdb61bfab6d0b9740591cd8bcb) for more info oon the story behind.
