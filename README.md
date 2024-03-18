# kr00tf1sh
linux desktop (KDE) root-access security breach (2007) suggesting ptrace_scope like solution into the kernel.

Proof of concept code for kde based gnu/linux systems, that was able to:
 - steal the entered password out of memory from the kdesu process
 - secretly execute other commands than the user wanted, then performing the users task
 - -> open the way for malware to gain root access due to desktop insecurity by design

(see [kro0tf1sh.c](https://github.com/M64GitHub/kr00tf1sh/blob/main/krootfish.c) for the final code)

See [gist](https://gist.github.com/M64GitHub/5353d9cdb61bfab6d0b9740591cd8bcb) for more info on the story behind.
