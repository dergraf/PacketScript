#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa3379c4b, "module_layout" },
	{ 0x5cf97727, "xt_unregister_target" },
	{ 0x9a1dfd65, "strpbrk" },
	{ 0x56fb5417, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xb85f3bbe, "pv_lock_ops" },
	{ 0x349cba85, "strchr" },
	{ 0xd0d8621b, "strlen" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x105e2727, "__tracepoint_kmalloc" },
	{ 0xbf7e1481, "inet_proto_csum_replace4" },
	{ 0x6c1ce5ce, "strcspn" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xe24d3a97, "jiffies_64" },
	{ 0x2bc95bd4, "memset" },
	{ 0x87fc9bcc, "kmem_cache_alloc_notrace" },
	{ 0x11089ac7, "_ctype" },
	{ 0x37befc70, "jiffies_to_msecs" },
	{ 0x70d1f8f3, "strncat" },
	{ 0xb72397d5, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x5152e605, "memcmp" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xc3fa6a59, "memchr" },
	{ 0x61651be, "strcat" },
	{ 0x7d8c0d13, "xt_register_target" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xbbe2391b, "kfree_skb" },
	{ 0xf333a2fb, "_raw_spin_lock_irq" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0x59e7cb79, "skb_make_writable" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x7d50a24, "csum_partial" },
	{ 0xc2d711e1, "krealloc" },
	{ 0xe914e41e, "strcpy" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=x_tables";


MODULE_INFO(srcversion, "33A1481C4AA71D1B5A8CA8A");
