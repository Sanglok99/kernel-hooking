#include <linux/module.h>
#include <linux/init.h>

extern long (*do_sys_open_module)(int dfd, const char __user *filename, int flags, umode_t mode);
extern long my_do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode); 

static int __init module_init_fs(void)
{
	do_sys_open_module = &my_do_sys_open;

	printk("start module\n");
	return 0;
}


static void __exit module_exit_fs(void)
{
	do_sys_open_module = 0;

	printk("end module\n");	
}

MODULE_LICENSE("GPL");
module_init(module_init_fs)
module_exit(module_exit_fs)
