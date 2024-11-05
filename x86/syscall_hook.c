#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/version.h>

#define MODULE_NAME "syscall_hook"
#define LOG_PREFIX MODULE_NAME ": "

MODULE_DESCRIPTION("A simple module that hooks the `mkdir` function, works on kernel 5.7 and higher.");
MODULE_AUTHOR("Joshua Lee <chengxun.li@seeed.cc>");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.0.1");

// For Linux 5.7 and higher versions, `kallsyms_lookup_name` is not exported anymore.
// But we can use `kprobe` to find the address of `kallsyms_lookup_name`.
// The `custom_kallsyms_lookup_name` represents the address of `kallsyms_lookup_name` internally.
// For kernel 5.7 and below, the `custom_kallsyms_lookup_name` simply calls to `kallsyms_lookup_name`.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
static kallsyms_lookup_name_t custom_kallsyms_lookup_name;
#else
#define custom_kallsyms_lookup_name kallsyms_lookup_name
#endif

// `fixup_kallsyms_lookup_name` extracts the address of `kallsyms_lookup_name` from `kprobe`.
// It returns 0 on success, -EFAULT on failure.
static int fixup_kallsyms_lookup_name(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    int result = register_kprobe(&kp);
    if (result < 0) {
        printk(KERN_ERR LOG_PREFIX "Failed to register kprobe, returned code: %d\n", result);
        return result;
    }
    custom_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if (!custom_kallsyms_lookup_name) {
        printk(KERN_ERR LOG_PREFIX "Failed to get address for `kallsyms_lookup_name`\n");
        return -EFAULT;
    }
    printk(KERN_DEBUG LOG_PREFIX "Got address for `kallsyms_lookup_name`: %p\n", custom_kallsyms_lookup_name);
    return 0;
#else
    return 0;
#endif
}

// `set_cr0_writable` disables write protection for CR0 and returns the original value of CR0.
static unsigned long set_cr0_writable(void) {
    unsigned long cr0;

#ifdef CONFIG_X86_64
    asm volatile("movq %%cr0, %%rax" : "=a"(cr0));
    unsigned long orig_cr0 = cr0;
    cr0 &= 0xfffeffff;
    asm volatile("movq %%rax, %%cr0" ::"a"(cr0));
#else
    asm volatile("movl %%cr0, %%eax" : "=a"(cr0));
    unsigned long orig_cr0 = cr0;
    cr0 &= 0xfffeffff;
    asm volatile("movl %%eax, %%cr0" ::"a"(cr0));
#endif

    return orig_cr0;
}

// `set_cr0_reg_val` sets CR0 to given value.
static void set_cr0_reg_val(unsigned long cr0) {
#ifdef CONFIG_X86_64
    asm volatile("movq %%rax, %%cr0" ::"a"(cr0));
#else
    asm volatile("movl %%eax, %%cr0" ::"a"(cr0));
#endif
}

typedef long (*syscall_fn_t)(const struct pt_regs* regs);  // `syscall_fn_t` is the type of system call.
static syscall_fn_t prototype_mkdir;                       // `prototype_mkdir` is backup of original `mkdir` function.
static unsigned long* syscall_table;                       // `syscall_table` points to the address of `sys_call_table`.

// `custom_mkdir` is our custom `mkdir` function.
// Do whatever you want here and return the result.
static int custom_mkdir(const struct pt_regs* regs) {
    printk(KERN_INFO LOG_PREFIX "`mkdir` function called by user\n");
    return prototype_mkdir(regs);  // Call original `mkdir`.
}

static int module_init_fn(void) {
    if (fixup_kallsyms_lookup_name() < 0) {
        return -1;
    }

    syscall_table = (unsigned long*)custom_kallsyms_lookup_name("sys_call_table");
    if (!syscall_table) {
        printk(KERN_ERR LOG_PREFIX "Could not find sys_call_table\n");
        return -1;
    }

    prototype_mkdir = (syscall_fn_t)syscall_table[__NR_mkdir];  // Create backup of original `mkdir` function.

    unsigned long cr0_val = set_cr0_writable();
    syscall_table[__NR_mkdir] = (unsigned long)custom_mkdir;  // Replace original `mkdir` with our custom one.
    set_cr0_reg_val(cr0_val);

    printk(KERN_INFO LOG_PREFIX "Hooked `mkdir` function successfully (%p => %p)\n", prototype_mkdir, custom_mkdir);
    return 0;
}

static void module_end_fn(void) {
    unsigned long cr0_val = set_cr0_writable();
    syscall_table[__NR_mkdir] = (unsigned long)prototype_mkdir;  // Restore original `mkdir` function.
    set_cr0_reg_val(cr0_val);

    printk(KERN_INFO LOG_PREFIX "Unhooked `mkdir` function successfully (%p => %p)\n", custom_mkdir, prototype_mkdir);
}

module_init(module_init_fn);
module_exit(module_end_fn);
