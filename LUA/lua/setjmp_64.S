#
# arch/i386/setjmp.S
#
# setjmp/longjmp for the i386 architecture
#

#
# The jmp_buf is assumed to contain the following, in order:
#	%ebx
#	%esp
#	%ebp
#	%esi
#	%edi
#	<return address>
#

#define _REGPARM

	.text
	.align 4
	.globl setjmp
	.type setjmp, @function
setjmp:
#ifdef _REGPARM
	movq %rax,%rdx
#else
	movq 4(%rsp),%rdx
#endif
	popq %rcx			# Return address, and adjust the stack
	xorq %rax,%rax			# Return value
	movq %rbx,(%rdx)
	movq %rsp,4(%rdx)		# Post-return %esp!
	pushq %rcx			# Make the call/return stack happy
	movq %rbp,8(%rdx)
	movq %rsi,12(%rdx)
	movq %rdi,16(%rdx)
	movq %rcx,20(%rdx)		# Return address
	ret

	.size setjmp,.-setjmp

	.text
	.align 4
	.globl longjmp
	.type longjmp, @function
longjmp:
#ifdef _REGPARM
	xchgq %rax,%rdx
#else
	movq 4(%rsp),%rdx		# jmp_ptr address
	movq 8(%rsp),%rax		# Return value
#endif
	movq (%rdx),%rbx
	movq 4(%rdx),%rsp
	movq 8(%rdx),%rbp
	movq 12(%rdx),%rsi
	movq 16(%rdx),%rdi
	jmp *20(%rdx)

	.size longjmp,.-longjmp

