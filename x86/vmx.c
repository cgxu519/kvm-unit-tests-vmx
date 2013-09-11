#include "libcflat.h"
#include "processor.h"
#include "vm.h"
#include "desc.h"
#include "vmx.h"
#include "msr.h"
#include "smp.h"
#include "io.h"

int fails, tests;
u32 *vmxon_region;
struct vmcs *vmcs_root;
u32 vpid_cnt;
void *guest_stack, *guest_syscall_stack;
u32 ctrl_pin, ctrl_enter, ctrl_exit, ctrl_cpu[2];
struct regs regs;
struct vmx_test *current;
u64 hypercall_field;
bool launched;
u64 host_rflags;

union vmx_basic basic;
union vmx_ctrl_pin ctrl_pin_rev;
union vmx_ctrl_cpu ctrl_cpu_rev[2];
union vmx_ctrl_exit ctrl_exit_rev;
union vmx_ctrl_ent ctrl_enter_rev;
union vmx_ept_vpid  ept_vpid;

extern u64 gdt64_desc[];
extern u64 idt_descr[];
extern u64 tss_descr[];
extern void *vmx_return;
extern void *entry_sysenter;
extern void *guest_entry;

void report(const char *name, int result)
{
	++tests;
	if (result)
		printf("PASS: %s\n", name);
	else {
		printf("FAIL: %s\n", name);
		++fails;
	}
}

/* entry_sysenter */
asm(
	".align	4, 0x90\n\t"
	".globl	entry_sysenter\n\t"
	"entry_sysenter:\n\t"
	SAVE_GPR
	"	and	$0xf, %rax\n\t"
	"	mov	%rax, %rdi\n\t"
	"	call	syscall_handler\n\t"
	LOAD_GPR
	"	vmresume\n\t"
);

static void __attribute__((__used__)) syscall_handler(u64 syscall_no)
{
	current->syscall_handler(syscall_no);
}

static inline int vmx_on()
{
	bool ret;
	asm volatile ("vmxon %1; setbe %0\n\t"
		: "=q"(ret) : "m"(vmxon_region) : "cc");
	return ret;
}

static inline int vmx_off()
{
	bool ret;
	asm volatile("vmxoff; setbe %0\n\t"
		: "=q"(ret) : : "cc");
	return ret;
}

void print_vmexit_info()
{
	u64 guest_rip, guest_rsp;
	ulong reason = vmcs_read(EXI_REASON) & 0xff;
	ulong exit_qual = vmcs_read(EXI_QUALIFICATION);
	guest_rip = vmcs_read(GUEST_RIP);
	guest_rsp = vmcs_read(GUEST_RSP);
	printf("VMEXIT info:\n");
	printf("\tvmexit reason = %d\n", reason);
	printf("\texit qualification = 0x%x\n", exit_qual);
	printf("\tBit 31 of reason = %x\n", (vmcs_read(EXI_REASON) >> 31) & 1);
	printf("\tguest_rip = 0x%llx\n", guest_rip);
	printf("\tRAX=0x%llx    RBX=0x%llx    RCX=0x%llx    RDX=0x%llx\n",
		regs.rax, regs.rbx, regs.rcx, regs.rdx);
	printf("\tRSP=0x%llx    RBP=0x%llx    RSI=0x%llx    RDI=0x%llx\n",
		guest_rsp, regs.rbp, regs.rsi, regs.rdi);
	printf("\tR8 =0x%llx    R9 =0x%llx    R10=0x%llx    R11=0x%llx\n",
		regs.r8, regs.r9, regs.r10, regs.r11);
	printf("\tR12=0x%llx    R13=0x%llx    R14=0x%llx    R15=0x%llx\n",
		regs.r12, regs.r13, regs.r14, regs.r15);
}

static void test_vmclear(void)
{
	u64 rflags;

	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	report("test vmclear", vmcs_clear(vmcs_root) == 0);
}

static void test_vmxoff(void)
{
	int ret;
	u64 rflags;

	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	ret = vmx_off();
	report("test vmxoff", !ret);
}

static void __attribute__((__used__)) guest_main(void)
{
	current->guest_main();
}

/* guest_entry */
asm(
	".align	4, 0x90\n\t"
	".globl	entry_guest\n\t"
	"guest_entry:\n\t"
	"	call guest_main\n\t"
	"	mov $1, %edi\n\t"
	"	call hypercall\n\t"
);

/* EPT paging structure related functions */
/* install_ept_entry : Install a page to a given level in EPT
		@pml4 : addr of pml4 table
		@pte_level : level of PTE to set
		@guest_addr : physical address of guest
		@pte : pte value to set
		@pt_page : address of page table, NULL for a new page
 */
void install_ept_entry(unsigned long *pml4,
		int pte_level,
		unsigned long guest_addr,
		unsigned long pte,
		unsigned long *pt_page)
{
	int level;
	unsigned long *pt = pml4;
	unsigned offset;

	for (level = EPT_PAGE_LEVEL; level > pte_level; --level) {
		offset = (guest_addr >> ((level-1) * EPT_PGDIR_WIDTH + 12))
				& EPT_PGDIR_MASK;
		if (!(pt[offset] & (EPT_PRESENT))) {
			unsigned long *new_pt = pt_page;
			if (!new_pt)
				new_pt = alloc_page();
			else
				pt_page = 0;
			memset(new_pt, 0, PAGE_SIZE);
			pt[offset] = virt_to_phys(new_pt)
					| EPT_RA | EPT_WA | EPT_EA;
		}
		pt = phys_to_virt(pt[offset] & 0xffffffffff000ull);
	}
	offset = ((unsigned long)guest_addr >> ((level-1) *
			EPT_PGDIR_WIDTH + 12)) & EPT_PGDIR_MASK;
	pt[offset] = pte;
}

/* Map a page, @perm is the permission of the page */
void install_ept(unsigned long *pml4,
		unsigned long phys,
		unsigned long guest_addr,
		u64 perm)
{
	install_ept_entry(pml4, 1, guest_addr, (phys & PAGE_MASK) | perm, 0);
}

/* Map a 1G-size page */
void install_1g_ept(unsigned long *pml4,
		unsigned long phys,
		unsigned long guest_addr,
		u64 perm)
{
	install_ept_entry(pml4, 3, guest_addr,
			(phys & PAGE_MASK) | perm | EPT_LARGE_PAGE, 0);
}

/* Map a 2M-size page */
void install_2m_ept(unsigned long *pml4,
		unsigned long phys,
		unsigned long guest_addr,
		u64 perm)
{
	install_ept_entry(pml4, 2, guest_addr,
			(phys & PAGE_MASK) | perm | EPT_LARGE_PAGE, 0);
}

/* setup_ept_range : Setup a range of 1:1 mapped page to EPT paging structure.
		@start : start address of guest page
		@len : length of address to be mapped
		@map_1g : whether 1G page map is used
		@map_2m : whether 2M page map is used
		@perm : permission for every page
 */
int setup_ept_range(unsigned long *pml4, unsigned long start,
		unsigned long len, int map_1g, int map_2m, u64 perm)
{
	u64 phys = start;
	u64 max = (u64)len + (u64)start;

	if (map_1g) {
		while (phys + PAGE_SIZE_1G <= max) {
			install_1g_ept(pml4, phys, phys, perm);
			phys += PAGE_SIZE_1G;
		}
	}
	if (map_2m) {
		while (phys + PAGE_SIZE_2M <= max) {
			install_2m_ept(pml4, phys, phys, perm);
			phys += PAGE_SIZE_2M;
		}
	}
	while (phys + PAGE_SIZE <= max) {
		install_ept(pml4, phys, phys, perm);
		phys += PAGE_SIZE;
	}
	return 0;
}

/* get_ept_pte : Get the PTE of a given level in EPT,
    @level == 1 means get the latest level*/
unsigned long get_ept_pte(unsigned long *pml4,
		unsigned long guest_addr, int level)
{
	int l;
	unsigned long *pt = pml4, pte;
	unsigned offset;

	for (l = EPT_PAGE_LEVEL; l > 1; --l) {
		offset = (guest_addr >> (((l-1) * EPT_PGDIR_WIDTH) + 12))
				& EPT_PGDIR_MASK;
		pte = pt[offset];
		if (!(pte & (EPT_PRESENT)))
			return 0;
		if (l == level)
			return pte;
		if (l < 4 && (pte & EPT_LARGE_PAGE))
			return pte;
		pt = (unsigned long *)(pte & 0xffffffffff000ull);
	}
	offset = (guest_addr >> (((l-1) * EPT_PGDIR_WIDTH) + 12))
			& EPT_PGDIR_MASK;
	pte = pt[offset];
	return pte;
}

int set_ept_pte(unsigned long *pml4, unsigned long guest_addr,
		int level, u64 pte_val)
{
	int l;
	unsigned long *pt = pml4;
	unsigned offset;

	if (level < 1 || level > 3)
		return -1;
	for (l = EPT_PAGE_LEVEL; l > 1; --l) {
		offset = (guest_addr >> (((l-1) * EPT_PGDIR_WIDTH) + 12))
				& EPT_PGDIR_MASK;
		if (l == level) {
			pt[offset] = pte_val;
			return 0;
		}
		if (!(pt[offset] & (EPT_PRESENT)))
			return -1;
		pt = (unsigned long *)(pt[offset] & 0xffffffffff000ull);
	}
	offset = (guest_addr >> (((l-1) * EPT_PGDIR_WIDTH) + 12))
			& EPT_PGDIR_MASK;
	pt[offset] = pte_val;
	return 0;
}


static void init_vmcs_ctrl(void)
{
	/* 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA */
	/* 26.2.1.1 */
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	/* Disable VMEXIT of IO instruction */
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	if (ctrl_cpu_rev[0].set & CPU_SECONDARY) {
		ctrl_cpu[1] = (ctrl_cpu[1] | ctrl_cpu_rev[1].set) &
			ctrl_cpu_rev[1].clr;
		vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	}
	vmcs_write(CR3_TARGET_COUNT, 0);
	vmcs_write(VPID, ++vpid_cnt);
}

static void init_vmcs_host(void)
{
	/* 26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA */
	/* 26.2.1.2 */
	vmcs_write(HOST_EFER, rdmsr(MSR_EFER));

	/* 26.2.1.3 */
	vmcs_write(ENT_CONTROLS, ctrl_enter);
	vmcs_write(EXI_CONTROLS, ctrl_exit);

	/* 26.2.2 */
	vmcs_write(HOST_CR0, read_cr0());
	vmcs_write(HOST_CR3, read_cr3());
	vmcs_write(HOST_CR4, read_cr4());
	vmcs_write(HOST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(HOST_SYSENTER_CS,  SEL_KERN_CODE_64);

	/* 26.2.3 */
	vmcs_write(HOST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(HOST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_FS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_GS, SEL_KERN_DATA_64);
	vmcs_write(HOST_SEL_TR, SEL_TSS_RUN);
	vmcs_write(HOST_BASE_TR,   (u64)tss_descr);
	vmcs_write(HOST_BASE_GDTR, (u64)gdt64_desc);
	vmcs_write(HOST_BASE_IDTR, (u64)idt_descr);
	vmcs_write(HOST_BASE_FS, 0);
	vmcs_write(HOST_BASE_GS, 0);

	/* Set other vmcs area */
	vmcs_write(PF_ERROR_MASK, 0);
	vmcs_write(PF_ERROR_MATCH, 0);
	vmcs_write(VMCS_LINK_PTR, ~0ul);
	vmcs_write(VMCS_LINK_PTR_HI, ~0ul);
	vmcs_write(HOST_RIP, (u64)(&vmx_return));
}

static void init_vmcs_guest(void)
{
	/* 26.3 CHECKING AND LOADING GUEST STATE */
	ulong guest_cr0, guest_cr4, guest_cr3;
	/* 26.3.1.1 */
	guest_cr0 = read_cr0();
	guest_cr4 = read_cr4();
	guest_cr3 = read_cr3();
	if (ctrl_enter & ENT_GUEST_64) {
		guest_cr0 |= X86_CR0_PG;
		guest_cr4 |= X86_CR4_PAE;
	}
	if ((ctrl_enter & ENT_GUEST_64) == 0)
		guest_cr4 &= (~X86_CR4_PCIDE);
	if (guest_cr0 & X86_CR0_PG)
		guest_cr0 |= X86_CR0_PE;
	vmcs_write(GUEST_CR0, guest_cr0);
	vmcs_write(GUEST_CR3, guest_cr3);
	vmcs_write(GUEST_CR4, guest_cr4);
	vmcs_write(GUEST_SYSENTER_CS,  SEL_KERN_CODE_64);
	vmcs_write(GUEST_SYSENTER_ESP,
		(u64)(guest_syscall_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_SYSENTER_EIP, (u64)(&entry_sysenter));
	vmcs_write(GUEST_DR7, 0);
	vmcs_write(GUEST_EFER, rdmsr(MSR_EFER));

	/* 26.3.1.2 */
	vmcs_write(GUEST_SEL_CS, SEL_KERN_CODE_64);
	vmcs_write(GUEST_SEL_SS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_DS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_ES, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_FS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_GS, SEL_KERN_DATA_64);
	vmcs_write(GUEST_SEL_TR, SEL_TSS_RUN);
	vmcs_write(GUEST_SEL_LDTR, 0);

	vmcs_write(GUEST_BASE_CS, 0);
	vmcs_write(GUEST_BASE_ES, 0);
	vmcs_write(GUEST_BASE_SS, 0);
	vmcs_write(GUEST_BASE_DS, 0);
	vmcs_write(GUEST_BASE_FS, 0);
	vmcs_write(GUEST_BASE_GS, 0);
	vmcs_write(GUEST_BASE_TR,   (u64)tss_descr);
	vmcs_write(GUEST_BASE_LDTR, 0);

	vmcs_write(GUEST_LIMIT_CS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_DS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_ES, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_SS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_FS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_GS, 0xFFFFFFFF);
	vmcs_write(GUEST_LIMIT_LDTR, 0xffff);
	vmcs_write(GUEST_LIMIT_TR, ((struct descr *)tss_descr)->limit);

	vmcs_write(GUEST_AR_CS, 0xa09b);
	vmcs_write(GUEST_AR_DS, 0xc093);
	vmcs_write(GUEST_AR_ES, 0xc093);
	vmcs_write(GUEST_AR_FS, 0xc093);
	vmcs_write(GUEST_AR_GS, 0xc093);
	vmcs_write(GUEST_AR_SS, 0xc093);
	vmcs_write(GUEST_AR_LDTR, 0x82);
	vmcs_write(GUEST_AR_TR, 0x8b);

	/* 26.3.1.3 */
	vmcs_write(GUEST_BASE_GDTR, (u64)gdt64_desc);
	vmcs_write(GUEST_BASE_IDTR, (u64)idt_descr);
	vmcs_write(GUEST_LIMIT_GDTR,
		((struct descr *)gdt64_desc)->limit & 0xffff);
	vmcs_write(GUEST_LIMIT_IDTR,
		((struct descr *)idt_descr)->limit & 0xffff);

	/* 26.3.1.4 */
	vmcs_write(GUEST_RIP, (u64)(&guest_entry));
	vmcs_write(GUEST_RSP, (u64)(guest_stack + PAGE_SIZE - 1));
	vmcs_write(GUEST_RFLAGS, 0x2);

	/* 26.3.1.5 */
	vmcs_write(GUEST_ACTV_STATE, 0);
	vmcs_write(GUEST_INTR_STATE, 0);
}

static int init_vmcs(struct vmcs **vmcs)
{
	*vmcs = alloc_page();
	memset(*vmcs, 0, PAGE_SIZE);
	(*vmcs)->revision_id = basic.revision;
	/* vmclear first to init vmcs */
	if (vmcs_clear(*vmcs)) {
		printf("%s : vmcs_clear error\n", __func__);
		return 1;
	}

	if (make_vmcs_current(*vmcs)) {
		printf("%s : make_vmcs_current error\n", __func__);
		return 1;
	}

	/* All settings to pin/exit/enter/cpu
	   control fields should be placed here */
	ctrl_pin |= PIN_EXTINT | PIN_NMI | PIN_VIRT_NMI;
	ctrl_exit = EXI_LOAD_EFER | EXI_HOST_64;
	ctrl_enter = (ENT_LOAD_EFER | ENT_GUEST_64);
	ctrl_cpu[0] |= CPU_HLT;
	/* DIsable IO instruction VMEXIT now */
	ctrl_cpu[0] &= (~(CPU_IO | CPU_IO_BITMAP));
	ctrl_cpu[1] = 0;

	ctrl_pin = (ctrl_pin | ctrl_pin_rev.set) & ctrl_pin_rev.clr;
	ctrl_enter = (ctrl_enter | ctrl_enter_rev.set) & ctrl_enter_rev.clr;
	ctrl_exit = (ctrl_exit | ctrl_exit_rev.set) & ctrl_exit_rev.clr;
	ctrl_cpu[0] = (ctrl_cpu[0] | ctrl_cpu_rev[0].set) & ctrl_cpu_rev[0].clr;

	init_vmcs_ctrl();
	init_vmcs_host();
	init_vmcs_guest();
	return 0;
}

static void init_vmx(void)
{
	ulong fix_cr0_set, fix_cr0_clr;
	ulong fix_cr4_set, fix_cr4_clr;

	vmxon_region = alloc_page();
	memset(vmxon_region, 0, PAGE_SIZE);

	fix_cr0_set =  rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	fix_cr0_clr =  rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	fix_cr4_set =  rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	fix_cr4_clr = rdmsr(MSR_IA32_VMX_CR4_FIXED1);
	basic.val = rdmsr(MSR_IA32_VMX_BASIC);
	ctrl_pin_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PIN
			: MSR_IA32_VMX_PINBASED_CTLS);
	ctrl_exit_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_EXIT
			: MSR_IA32_VMX_EXIT_CTLS);
	ctrl_enter_rev.val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_ENTRY
			: MSR_IA32_VMX_ENTRY_CTLS);
	ctrl_cpu_rev[0].val = rdmsr(basic.ctrl ? MSR_IA32_VMX_TRUE_PROC
			: MSR_IA32_VMX_PROCBASED_CTLS);
	if ((ctrl_cpu_rev[0].clr & CPU_SECONDARY) != 0)
		ctrl_cpu_rev[1].val = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	else
		ctrl_cpu_rev[1].val = 0;
	if ((ctrl_cpu_rev[1].clr & (CPU_EPT | CPU_VPID)) != 0)
		ept_vpid.val = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	else
		ept_vpid.val = 0;

	write_cr0((read_cr0() & fix_cr0_clr) | fix_cr0_set);
	write_cr4((read_cr4() & fix_cr4_clr) | fix_cr4_set | X86_CR4_VMXE);

	*vmxon_region = basic.revision;

	guest_stack = alloc_page();
	memset(guest_stack, 0, PAGE_SIZE);
	guest_syscall_stack = alloc_page();
	memset(guest_syscall_stack, 0, PAGE_SIZE);
}

static int test_vmx_capability(void)
{
	struct cpuid r;
	u64 ret1, ret2;
	u64 ia32_feature_control;
	r = cpuid(1);
	ret1 = ((r.c) >> 5) & 1;
	ia32_feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	ret2 = ((ia32_feature_control & 0x5) == 0x5);
	if ((!ret2) && ((ia32_feature_control & 0x1) == 0)) {
		wrmsr(MSR_IA32_FEATURE_CONTROL, 0x5);
		ia32_feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
		ret2 = ((ia32_feature_control & 0x5) == 0x5);
	}
	report("test vmx capability", ret1 & ret2);
	return !(ret1 & ret2);
}

static int test_vmxon(void)
{
	int ret;
	u64 rflags;

	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	ret = vmx_on();
	report("test vmxon", !ret);
	return ret;
}

static void test_vmptrld(void)
{
	u64 rflags;
	struct vmcs *vmcs;

	vmcs = alloc_page();
	vmcs->revision_id = basic.revision;
	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	report("test vmptrld", make_vmcs_current(vmcs) == 0);
}

static void test_vmptrst(void)
{
	u64 rflags;
	int ret;
	struct vmcs *vmcs1, *vmcs2;

	vmcs1 = alloc_page();
	memset(vmcs1, 0, PAGE_SIZE);
	init_vmcs(&vmcs1);
	rflags = read_rflags() | X86_EFLAGS_CF | X86_EFLAGS_ZF;
	write_rflags(rflags);
	ret = vmcs_save(&vmcs2);
	report("test vmptrst", (!ret) && (vmcs1 == vmcs2));
}

/* This function can only be called in guest */
static void __attribute__((__used__)) hypercall(u32 hypercall_no)
{
	u64 val = 0;
	val = (hypercall_no & HYPERCALL_MASK) | HYPERCALL_BIT;
	hypercall_field = val;
	asm volatile("vmcall\n\t");
}

static bool is_hypercall()
{
	ulong reason, hyper_bit;

	reason = vmcs_read(EXI_REASON) & 0xff;
	hyper_bit = hypercall_field & HYPERCALL_BIT;
	if (reason == VMX_VMCALL && hyper_bit)
		return true;
	return false;
}

static int handle_hypercall()
{
	ulong hypercall_no;

	hypercall_no = hypercall_field & HYPERCALL_MASK;
	hypercall_field = 0;
	switch (hypercall_no) {
	case HYPERCALL_VMEXIT:
		return VMX_TEST_VMEXIT;
	default:
		printf("ERROR : Invalid hypercall number : %d\n", hypercall_no);
	}
	return VMX_TEST_EXIT;
}

static int exit_handler()
{
	int ret;

	current->exits++;
	regs.rflags = vmcs_read(GUEST_RFLAGS);
	if (is_hypercall())
		ret = handle_hypercall();
	else
		ret = current->exit_handler();
	vmcs_write(GUEST_RFLAGS, regs.rflags);
	switch (ret) {
	case VMX_TEST_VMEXIT:
	case VMX_TEST_RESUME:
		return ret;
	case VMX_TEST_EXIT:
		break;
	default:
		printf("ERROR : Invalid exit_handler return val %d.\n"
			, ret);
	}
	print_vmexit_info();
	exit(-1);
	return 0;
}

static int vmx_run()
{
	u32 ret = 0, fail = 0;
	bool entry_double_fail = false;

	while (1) {
		asm volatile (
			"mov %%rsp, %%rsi\n\t"
			"mov %2, %%rdi\n\t"
			"vmwrite %%rsi, %%rdi\n\t"

			LOAD_GPR_C
			"cmpl $0, %1\n\t"
			"jne 1f\n\t"
			LOAD_RFLAGS
			"vmlaunch\n\t"
			"jmp 2f\n\t"
			"1: "
			"vmresume\n\t"
			"2: "
			"setbe %0\n\t"
			"vmx_return:\n\t"
			SAVE_GPR_C
			SAVE_RFLAGS
			: "=m"(fail)
			: "m"(launched), "i"(HOST_RSP)
			: "rdi", "rsi", "memory", "cc"

		);
		if (fail)
			if (entry_double_fail)
				ret = launched ? VMX_TEST_RESUME_ERR :
					VMX_TEST_LAUNCH_ERR;
			else {
				ret = current->entry_failed_handler(launched);
				if (ret == VMX_TEST_RESUME) {
					entry_double_fail = true;
					host_rflags &= ~(X86_EFLAGS_ZF |
						X86_EFLAGS_CF);
				}
			}
		else {
			launched = 1;
			entry_double_fail = false;
			ret = exit_handler();
		}
		if (ret != VMX_TEST_RESUME)
			break;
		ret = fail = 0;
	}
	launched = 0;
	switch (ret) {
	case VMX_TEST_VMEXIT:
		return 0;
	case VMX_TEST_LAUNCH_ERR:
		printf("%s : vmlaunch failed, entry_double_fail=%d.\n",
			__func__, entry_double_fail);
		if ((!(host_rflags & X86_EFLAGS_CF) && !(host_rflags & X86_EFLAGS_ZF))
			|| ((host_rflags & X86_EFLAGS_CF) && (host_rflags & X86_EFLAGS_ZF)))
			printf("\tvmlaunch set wrong flags\n");
		report("test vmlaunch", 0);
		break;
	case VMX_TEST_RESUME_ERR:
		printf("%s : vmresume failed, entry_double_fail=%d.\n",
			__func__, entry_double_fail);
		if ((!(host_rflags & X86_EFLAGS_CF) && !(host_rflags & X86_EFLAGS_ZF))
			|| ((host_rflags & X86_EFLAGS_CF) && (host_rflags & X86_EFLAGS_ZF)))
			printf("\tvmresume set wrong flags\n");
		report("test vmresume", 0);
		break;
	default:
		printf("%s : unhandled ret from exit_handler, ret=%d.\n", __func__, ret);
		break;
	}
	return 1;
}

static int test_run(struct vmx_test *test)
{
	if (test->name == NULL)
		test->name = "(no name)";
	if (vmx_on()) {
		printf("%s : vmxon failed.\n", __func__);
		return 1;
	}
	init_vmcs(&(test->vmcs));
	current = test;
	/* Directly call test->init is ok here, init_vmcs has done
	   vmcs init, vmclear and vmptrld*/
	if (test->init)
		test->init();
	test->exits = 0;
	regs = test->guest_regs;
	vmcs_write(GUEST_RFLAGS, regs.rflags | 0x2);
	launched = 0;
	printf("\nTest suite : %s\n", test->name);
	vmx_run();
	if (vmx_off()) {
		printf("%s : vmxoff failed.\n", __func__);
		return 1;
	}
	return 0;
}

extern struct vmx_test vmx_tests[];

int main(void)
{
	int i = 0;

	setup_vm();
	setup_idt();
	fails = tests = 0;
	hypercall_field = 0;

	if (test_vmx_capability() != 0) {
		printf("ERROR : vmx not supported, check +vmx option\n");
		goto exit;
	}
	init_vmx();
	/* Set basic test ctxt the same as "null" */
	current = &vmx_tests[0];
	if (test_vmxon() != 0)
		goto exit;
	test_vmptrld();
	test_vmclear();
	test_vmptrst();
	init_vmcs(&vmcs_root);
	if (vmx_run()) {
		report("test vmlaunch", 0);
		goto exit;
	}
	test_vmxoff();

	while (vmx_tests[++i].name != NULL)
		if (test_run(&vmx_tests[i]))
			goto exit;

exit:
	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}
