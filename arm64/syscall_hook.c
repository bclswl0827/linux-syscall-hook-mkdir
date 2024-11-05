#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

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

struct vm_struct* (*custom_find_vm_area)(const void* base_addr);      // `custom_find_vm_area` points to the address of `find_vm_area` function.
int (*custom_set_memory_rw)(unsigned long base_addr, int num_pages);  // `custom_set_memory_rw` points to the address of `set_memory_rw` function.
int (*custom_set_memory_ro)(unsigned long base_addr, int num_pages);  // `custom_set_memory_ro` points to the address of `set_memory_ro` function.
static unsigned long syscall_target_base_addr;                        // `syscall_target_base_addr` is the base address of target system call.

typedef long (*syscall_fn_t)(const struct pt_regs* regs);  // `syscall_fn_t` is the type of any system call.
static syscall_fn_t prototype_mkdir;                       // `prototype_mkdir` is backup of original `mkdir` function.
static unsigned long* syscall_table;                       // `syscall_table` points to the address of `sys_call_table`.

// `custom_mkdir` is our custom `mkdir` function.
// Do whatever you want here and return the result.
static int custom_mkdir(const struct pt_regs* regs) {
    char filename[512] = {0};
    char __user* pathname = (char*)regs->regs[1];
    if (copy_from_user(filename, pathname, sizeof(filename)) != 0) {
        printk(KERN_ERR LOG_PREFIX "Failed to get file name from user\n");
        return -1;
    }
    printk(KERN_INFO LOG_PREFIX "`mkdir` function called by user, file name: %s\n", filename);
    return prototype_mkdir(regs);  // Call original `mkdir`.
}

static int module_init_fn(void) {
    if (fixup_kallsyms_lookup_name() < 0) {
        return -1;
    }

    custom_set_memory_ro = (void*)custom_kallsyms_lookup_name("set_memory_ro");
    if (custom_set_memory_ro == NULL) {
        printk(KERN_ERR LOG_PREFIX "Could not find `set_memory_ro`\n");
        return -1;
    }

    custom_set_memory_rw = (void*)custom_kallsyms_lookup_name("set_memory_rw");
    if (custom_set_memory_rw == NULL) {
        printk(KERN_ERR LOG_PREFIX "Could not find `set_memory_rw`\n");
        return -1;
    }

    custom_find_vm_area = (void*)custom_kallsyms_lookup_name("find_vm_area");
    if (custom_find_vm_area == NULL) {
        printk(KERN_ERR LOG_PREFIX "Could not find `find_vm_area`\n");
        return -1;
    }

    syscall_table = (unsigned long*)custom_kallsyms_lookup_name("sys_call_table");
    if (syscall_table == NULL) {
        printk(KERN_ERR LOG_PREFIX "Could not find `sys_call_table`\n");
        return -1;
    }
    prototype_mkdir = (syscall_fn_t)syscall_table[__NR_mkdirat];  // Create backup of original `mkdir` function.

    syscall_target_base_addr = ((unsigned long)(syscall_table + __NR_mkdirat)) & PAGE_MASK;
    struct vm_struct* area = custom_find_vm_area((void*)syscall_target_base_addr);
    if (area == NULL) {
        printk(KERN_ERR LOG_PREFIX "Could not find vm area\n");
        return -1;
    }
    area->flags |= VM_ALLOC;

    int result = custom_set_memory_rw(syscall_target_base_addr, 1);
    if (result != 0) {
        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read/write mode\n");
        return -1;
    }
    syscall_table[__NR_mkdirat] = (unsigned long)custom_mkdir;  // Replace original `mkdir` with our custom one.
    result = custom_set_memory_ro(syscall_target_base_addr, 1);
    if (result != 0) {
        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read-only mode\n");
        return -1;
    }

    printk(KERN_INFO LOG_PREFIX "Hooked `mkdir` function successfully (%p => %p)\n", prototype_mkdir, custom_mkdir);
    return 0;
}

static void module_end_fn(void) {
    int result = custom_set_memory_rw(syscall_target_base_addr, 1);
    if (result != 0) {
        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read/write mode\n");
        return;
    }
    syscall_table[__NR_mkdirat] = (unsigned long)prototype_mkdir;  // Restore original `mkdir` function.
    result = custom_set_memory_ro(syscall_target_base_addr, 1);
    if (result != 0) {
        printk(KERN_ERR LOG_PREFIX "Failed to set memory to read-only mode\n");
        return;
    }

    printk(KERN_INFO LOG_PREFIX "Unhooked `mkdir` function successfully (%p => %p)\n", custom_mkdir, prototype_mkdir);
}

module_init(module_init_fn);
module_exit(module_end_fn);
