// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>
#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "showmappings", "Display physical page mappings", mon_showmappings},
	{ "modify", "Modify permission bits", mon_modify},
	{ "dump","dump the contents of a range VA/PA address range ", mon_dump}
};
/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	unsigned int *ebp = ((unsigned int*)read_ebp());
	cprintf("Stack backtrace:\n");

	while(ebp) {
		cprintf("ebp %08x ", ebp);
		cprintf("eip %08x args", ebp[1]);
		for(int i = 2; i <= 6; i++)
			cprintf(" %08x", ebp[i]);
		cprintf("\n");

		unsigned int eip = ebp[1];
		struct Eipdebuginfo info;
		debuginfo_eip(eip, &info);
		cprintf("\t%s:%d: %.*s+%d\n",
		info.eip_file, info.eip_line,
		info.eip_fn_namelen, info.eip_fn_name,
		eip-info.eip_fn_addr);

		ebp = (unsigned int*)(*ebp);
	}
	return 0;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
    if (argc<3)
    {
        cprintf("Error: not enough parameter\n");
        return -1;
    }
    uintptr_t startADDR = strtol(argv[1],NULL,16);
    uintptr_t endADDR = strtol(argv[2],NULL,16);
    int cnt = ((endADDR - startADDR)>>12)&0xFFFFFF;
    cprintf("     VADDR          PADDR     PTE_U  PTE_W  PTE_P\n");
    for (int i = 0 ; i < cnt ; i++)
    {
        uintptr_t va = startADDR + i * 0x1000;
        cprintf("   %x   ",va);
        pte_t * entry ;
        struct PageInfo *pginfo = page_lookup(kern_pgdir,(void *)va,&entry);
        if (pginfo == NULL)
        {
            cprintf("       None     ");
            cprintf("       None ");
            cprintf("  None");
            cprintf("  None\n");
        }
        else
        {
            physaddr_t pa = PTE_ADDR(*entry);
            cprintf("       x    ",pa);
            cprintf("     %d      %d     %d\n",1-!(*entry&PTE_U),1-!(*entry&PTE_W),1-!(*entry&PTE_P));
        }
    }   
    return 0;
}

int
mon_modify(int argc, char **argv, struct Trapframe *tf)
{
    	uintptr_t va = strtol(argv[1],NULL,16);
    	pte_t * entry = pgdir_walk(kern_pgdir,(void *)va,0);
	if (entry == NULL)
    	{
        	cprintf("Page table entry not exist!\n");
        	return -1;
    	}
	char opt = argv[2][0];
	if (opt != 'c' && opt != 's')
	{
		cprintf("Error: unknown option");
		return -1;
	}
	char opnd = argv[3][0];
	if (opnd != 'P' && opnd != 'U' && opnd != 'W')
	{
		cprintf("Error: unknown permission bit");
		return -1;
	}
	if (opt == 'c')
	{
		if (opnd == 'P')
		{
			*entry = (*entry) & (~PTE_P);
		}
		if (opnd == 'U')
		{
			*entry = (*entry) & (~PTE_U);
		}
		if (opnd == 'W')
		{
			*entry = (*entry) & (~PTE_W);
		}
	}
	else if (opt == 's')
	{
		if (opnd == 'P')
		{
			*entry = (*entry) | (PTE_P);
		}
		if (opnd == 'U')
		{
			*entry = (*entry) | (PTE_U);
		}
		if (opnd == 'W')
		{
			*entry = (*entry) | (PTE_W);
		}
	}
	return 0;
}

int 
mon_dump(int argc, char **argv, struct Trapframe *tf)
{
    if (argc<4)
    {
        cprintf("usage: mem [VA/PA(start)]  [VA/PA(end)] P|V \n");
        return -1;
    }
    uintptr_t startADDR = strtol(argv[1],NULL,16);
    uintptr_t endADDR = strtol(argv[2],NULL,16);
    char type = argv[3][0];
    if (type != 'P' && type != 'V')
    {
        cprintf("usage: mem [VA/PA(start)]  [VA/PA(end)] P|V \n");
        return -1;
    }


    uintptr_t startVA,endVA;
    if (type == 'P')
    {
        startADDR += KERNBASE;
        endADDR += KERNBASE;
    }
    startADDR = ROUNDUP(startADDR,4);
    endADDR = ROUNDUP(endADDR,4);
    int cnt = ((endADDR - startADDR)>>2);;
    cprintf("startADDR: x endADDR:x cnt:%d\n",startADDR,endADDR,cnt);
    for ( int i = 0 ; i < cnt ; i++)
    {
        void ** va = (void **)startADDR + i;
        cprintf("[x]:x\n",va,*va);
    }

    return 0;

}
/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
