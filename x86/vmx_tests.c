#include "vmx.h"
#include "msr.h"
#include "processor.h"
#include "vm.h"
#include "io.h"
#include "fwcfg.h"

u64 ia32_pat;
u64 ia32_efer;
volatile u32 stage;
void *io_bitmap_a, *io_bitmap_b;
u16 ioport;

bool init_fail;
unsigned long *pml4;
u64 eptp;
void *data_page1, *data_page2;
static u32 cur_test;
volatile static bool test_success;
static u32 phy_addr_width;

extern struct vmx_test *current;
extern u64 host_rflags;
extern bool launched;

static inline void vmcall()
{
	asm volatile("vmcall");
}

static inline void set_stage(u32 s)
{
	barrier();
	stage = s;
	barrier();
}

static inline u32 get_stage()
{
	u32 s;

	barrier();
	s = stage;
	barrier();
	return s;
}

void basic_init()
{
}

void basic_guest_main()
{
	/* Here is a basic guest_main, print Hello World */
	printf("\tHello World, this is null_guest_main!\n");
}

int basic_exit_handler()
{
	u64 guest_rip;
	ulong reason;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;

	switch (reason) {
	case VMX_VMCALL:
		print_vmexit_info();
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		break;
	}
	printf("ERROR : Unhandled vmx exit.\n");
	print_vmexit_info();
	return VMX_TEST_EXIT;
}

void basic_syscall_handler(u64 syscall_no)
{
}

int basic_entry_failed_handler()
{
	return launched ? VMX_TEST_RESUME_ERR :
			VMX_TEST_LAUNCH_ERR;
}

void vmenter_main()
{
	u64 rax;
	u64 rsp, resume_rsp;

	report("test vmlaunch", 1);

	asm volatile(
		"mov %%rsp, %0\n\t"
		"mov %3, %%rax\n\t"
		"vmcall\n\t"
		"mov %%rax, %1\n\t"
		"mov %%rsp, %2\n\t"
		: "=r"(rsp), "=r"(rax), "=r"(resume_rsp)
		: "g"(0xABCD));
	report("test vmresume", (rax == 0xFFFF) && (rsp == resume_rsp));
}

int vmenter_exit_handler()
{
	u64 guest_rip;
	ulong reason;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		if (regs.rax != 0xABCD) {
			report("test vmresume", 0);
			return VMX_TEST_VMEXIT;
		}
		regs.rax = 0xFFFF;
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		report("test vmresume", 0);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

u32 preempt_scale;
volatile unsigned long long tsc_val;
volatile u32 preempt_val;

void preemption_timer_init()
{
	u32 ctrl_pin;

	ctrl_pin = vmcs_read(PIN_CONTROLS) | PIN_PREEMPT;
	ctrl_pin &= ctrl_pin_rev.clr;
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	preempt_val = 10000000;
	vmcs_write(PREEMPT_TIMER_VALUE, preempt_val);
	preempt_scale = rdmsr(MSR_IA32_VMX_MISC) & 0x1F;
}

void preemption_timer_main()
{
	tsc_val = rdtsc();
	if (!(ctrl_pin_rev.clr & PIN_PREEMPT)) {
		printf("\tPreemption timer is not supported\n");
		return;
	}
	if (!(ctrl_exit_rev.clr & EXI_SAVE_PREEMPT))
		printf("\tSave preemption value is not supported\n");
	else {
		set_stage(0);
		vmcall();
		if (get_stage() == 1)
			vmcall();
	}
	while (1) {
		if (((rdtsc() - tsc_val) >> preempt_scale)
				> 10 * preempt_val) {
			report("Preemption timer", 0);
			break;
		}
	}
}

int preemption_timer_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	u32 ctrl_exit;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (reason) {
	case VMX_PREEMPT:
		if (((rdtsc() - tsc_val) >> preempt_scale) < preempt_val)
			report("Preemption timer", 0);
		else
			report("Preemption timer", 1);
		return VMX_TEST_VMEXIT;
	case VMX_VMCALL:
		switch (get_stage()) {
		case 0:
			if (vmcs_read(PREEMPT_TIMER_VALUE) != preempt_val)
				report("Save preemption value", 0);
			else {
				set_stage(get_stage() + 1);
				ctrl_exit = (vmcs_read(EXI_CONTROLS) |
					EXI_SAVE_PREEMPT) & ctrl_exit_rev.clr;
				vmcs_write(EXI_CONTROLS, ctrl_exit);
			}
			break;
		case 1:
			if (vmcs_read(PREEMPT_TIMER_VALUE) >= preempt_val)
				report("Save preemption value", 0);
			else
				report("Save preemption value", 1);
			break;
		default:
			printf("Invalid stage.\n");
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		printf("Unknown exit reason, %d\n", reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

void msr_bmp_init()
{
	void *msr_bitmap;
	u32 ctrl_cpu0;

	msr_bitmap = alloc_page();
	memset(msr_bitmap, 0x0, PAGE_SIZE);
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_MSR_BITMAP;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(MSR_BITMAP, (u64)msr_bitmap);
}

static void test_ctrl_pat_init()
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	ctrl_ent = vmcs_read(ENT_CONTROLS);
	ctrl_exi = vmcs_read(EXI_CONTROLS);
	vmcs_write(ENT_CONTROLS, ctrl_ent | ENT_LOAD_PAT);
	vmcs_write(EXI_CONTROLS, ctrl_exi | (EXI_SAVE_PAT | EXI_LOAD_PAT));
	ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	vmcs_write(GUEST_PAT, 0x0);
	vmcs_write(HOST_PAT, ia32_pat);
}

static void test_ctrl_pat_main()
{
	u64 guest_ia32_pat;

	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_PAT))
		printf("\tENT_LOAD_PAT is not supported.\n");
	else {
		if (guest_ia32_pat != 0) {
			report("Entry load PAT", 0);
			return;
		}
	}
	wrmsr(MSR_IA32_CR_PAT, 0x6);
	vmcall();
	guest_ia32_pat = rdmsr(MSR_IA32_CR_PAT);
	if (ctrl_enter_rev.clr & ENT_LOAD_PAT) {
		if (guest_ia32_pat != ia32_pat) {
			report("Entry load PAT", 0);
			return;
		}
		report("Entry load PAT", 1);
	}
}

static int test_ctrl_pat_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u64 guest_pat;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		guest_pat = vmcs_read(GUEST_PAT);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_PAT)) {
			printf("\tEXI_SAVE_PAT is not supported\n");
			vmcs_write(GUEST_PAT, 0x6);
		} else {
			if (guest_pat == 0x6)
				report("Exit save PAT", 1);
			else
				report("Exit save PAT", 0);
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_PAT))
			printf("\tEXI_LOAD_PAT is not supported\n");
		else {
			if (rdmsr(MSR_IA32_CR_PAT) == ia32_pat)
				report("Exit load PAT", 1);
			else
				report("Exit load PAT", 0);
		}
		vmcs_write(GUEST_PAT, ia32_pat);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Undefined exit reason, reason = %d.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

static void test_ctrl_efer_init()
{
	u64 ctrl_ent;
	u64 ctrl_exi;

	msr_bmp_init();
	ctrl_ent = vmcs_read(ENT_CONTROLS) | ENT_LOAD_EFER;
	ctrl_exi = vmcs_read(EXI_CONTROLS) | EXI_SAVE_EFER | EXI_LOAD_EFER;
	vmcs_write(ENT_CONTROLS, ctrl_ent & ctrl_enter_rev.clr);
	vmcs_write(EXI_CONTROLS, ctrl_exi & ctrl_exit_rev.clr);
	ia32_efer = rdmsr(MSR_EFER);
	vmcs_write(GUEST_EFER, ia32_efer ^ EFER_NX);
	vmcs_write(HOST_EFER, ia32_efer ^ EFER_NX);
}

static void test_ctrl_efer_main()
{
	u64 guest_ia32_efer;

	guest_ia32_efer = rdmsr(MSR_EFER);
	if (!(ctrl_enter_rev.clr & ENT_LOAD_EFER))
		printf("\tENT_LOAD_EFER is not supported.\n");
	else {
		if (guest_ia32_efer != (ia32_efer ^ EFER_NX)) {
			report("Entry load EFER", 0);
			return;
		}
	}
	wrmsr(MSR_EFER, ia32_efer);
	vmcall();
	guest_ia32_efer = rdmsr(MSR_EFER);
	if (ctrl_enter_rev.clr & ENT_LOAD_EFER) {
		if (guest_ia32_efer != ia32_efer) {
			report("Entry load EFER", 0);
			return;
		}
		report("Entry load EFER", 1);
	}
}

static int test_ctrl_efer_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u64 guest_efer;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	switch (reason) {
	case VMX_VMCALL:
		guest_efer = vmcs_read(GUEST_EFER);
		if (!(ctrl_exit_rev.clr & EXI_SAVE_EFER)) {
			printf("\tEXI_SAVE_EFER is not supported\n");
			vmcs_write(GUEST_EFER, ia32_efer);
		} else {
			if (guest_efer == ia32_efer)
				report("Exit save EFER", 1);
			else
				report("Exit save EFER", 0);
		}
		if (!(ctrl_exit_rev.clr & EXI_LOAD_EFER)) {
			printf("\tEXI_LOAD_EFER is not supported\n");
			wrmsr(MSR_EFER, ia32_efer ^ EFER_NX);
		} else {
			if (rdmsr(MSR_EFER) == (ia32_efer ^ EFER_NX))
				report("Exit load EFER", 1);
			else
				report("Exit load EFER", 0);
		}
		vmcs_write(GUEST_PAT, ia32_efer);
		vmcs_write(GUEST_RIP, guest_rip + 3);
		return VMX_TEST_RESUME;
	default:
		printf("ERROR : Undefined exit reason, reason = %d.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

u32 guest_cr0, guest_cr4;

static void cr_shadowing_main()
{
	u32 cr0, cr4, tmp;

	// Test read through
	set_stage(0);
	guest_cr0 = read_cr0();
	if (stage == 1)
		report("Read through CR0", 0);
	else
		vmcall();
	set_stage(1);
	guest_cr4 = read_cr4();
	if (stage == 2)
		report("Read through CR4", 0);
	else
		vmcall();
	// Test write through
	guest_cr0 = guest_cr0 ^ (X86_CR0_TS | X86_CR0_MP);
	guest_cr4 = guest_cr4 ^ (X86_CR4_TSD | X86_CR4_DE);
	set_stage(2);
	write_cr0(guest_cr0);
	if (stage == 3)
		report("Write throuth CR0", 0);
	else
		vmcall();
	set_stage(3);
	write_cr4(guest_cr4);
	if (stage == 4)
		report("Write through CR4", 0);
	else
		vmcall();
	// Test read shadow
	set_stage(4);
	vmcall();
	cr0 = read_cr0();
	if (stage != 5) {
		if (cr0 == guest_cr0)
			report("Read shadowing CR0", 1);
		else
			report("Read shadowing CR0", 0);
	}
	set_stage(5);
	cr4 = read_cr4();
	if (stage != 6) {
		if (cr4 == guest_cr4)
			report("Read shadowing CR4", 1);
		else
			report("Read shadowing CR4", 0);
	}
	// Test write shadow (same value with shadow)
	set_stage(6);
	write_cr0(guest_cr0);
	if (stage == 7)
		report("Write shadowing CR0 (same value with shadow)", 0);
	else
		vmcall();
	set_stage(7);
	write_cr4(guest_cr4);
	if (stage == 8)
		report("Write shadowing CR4 (same value with shadow)", 0);
	else
		vmcall();
	// Test write shadow (different value)
	set_stage(8);
	tmp = guest_cr0 ^ X86_CR0_TS;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 9)
		report("Write shadowing different X86_CR0_TS", 0);
	else
		report("Write shadowing different X86_CR0_TS", 1);
	set_stage(9);
	tmp = guest_cr0 ^ X86_CR0_MP;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr0\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 10)
		report("Write shadowing different X86_CR0_MP", 0);
	else
		report("Write shadowing different X86_CR0_MP", 1);
	set_stage(10);
	tmp = guest_cr4 ^ X86_CR4_TSD;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 11)
		report("Write shadowing different X86_CR4_TSD", 0);
	else
		report("Write shadowing different X86_CR4_TSD", 1);
	set_stage(11);
	tmp = guest_cr4 ^ X86_CR4_DE;
	asm volatile("mov %0, %%rsi\n\t"
		"mov %%rsi, %%cr4\n\t"
		::"m"(tmp)
		:"rsi", "memory", "cc");
	if (stage != 12)
		report("Write shadowing different X86_CR4_DE", 0);
	else
		report("Write shadowing different X86_CR4_DE", 1);
}

static int cr_shadowing_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	u32 exit_qual;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	switch (reason) {
	case VMX_VMCALL:
		switch (stage) {
		case 0:
			if (guest_cr0 == vmcs_read(GUEST_CR0))
				report("Read through CR0", 1);
			else
				report("Read through CR0", 0);
			break;
		case 1:
			if (guest_cr4 == vmcs_read(GUEST_CR4))
				report("Read through CR4", 1);
			else
				report("Read through CR4", 0);
			break;
		case 2:
			if (guest_cr0 == vmcs_read(GUEST_CR0))
				report("Write through CR0", 1);
			else
				report("Write through CR0", 0);
			break;
		case 3:
			if (guest_cr4 == vmcs_read(GUEST_CR4))
				report("Write through CR4", 1);
			else
				report("Write through CR4", 0);
			break;
		case 4:
			guest_cr0 = vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP);
			guest_cr4 = vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE);
			vmcs_write(CR0_MASK, X86_CR0_TS | X86_CR0_MP);
			vmcs_write(CR0_READ_SHADOW, guest_cr0 & (X86_CR0_TS | X86_CR0_MP));
			vmcs_write(CR4_MASK, X86_CR4_TSD | X86_CR4_DE);
			vmcs_write(CR4_READ_SHADOW, guest_cr4 & (X86_CR4_TSD | X86_CR4_DE));
			break;
		case 6:
			if (guest_cr0 == (vmcs_read(GUEST_CR0) ^ (X86_CR0_TS | X86_CR0_MP)))
				report("Write shadowing CR0 (same value)", 1);
			else
				report("Write shadowing CR0 (same value)", 0);
			break;
		case 7:
			if (guest_cr4 == (vmcs_read(GUEST_CR4) ^ (X86_CR4_TSD | X86_CR4_DE)))
				report("Write shadowing CR4 (same value)", 1);
			else
				report("Write shadowing CR4 (same value)", 0);
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_CR:
		switch (stage) {
		case 4:
			report("Read shadowing CR0", 0);
			set_stage(stage + 1);
			break;
		case 5:
			report("Read shadowing CR4", 0);
			set_stage(stage + 1);
			break;
		case 6:
			report("Write shadowing CR0 (same value)", 0);
			set_stage(stage + 1);
			break;
		case 7:
			report("Write shadowing CR4 (same value)", 0);
			set_stage(stage + 1);
			break;
		case 8:
		case 9:
			// 0x600 encodes "mov %esi, %cr0"
			if (exit_qual == 0x600)
				set_stage(stage + 1);
			break;
		case 10:
		case 11:
			// 0x604 encodes "mov %esi, %cr4"
			if (exit_qual == 0x604)
				set_stage(stage + 1);
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		printf("Unknown exit reason, %d\n", reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static void iobmp_init()
{
	u32 ctrl_cpu0;

	io_bitmap_a = alloc_page();
	io_bitmap_a = alloc_page();
	memset(io_bitmap_a, 0x0, PAGE_SIZE);
	memset(io_bitmap_b, 0x0, PAGE_SIZE);
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_IO_BITMAP;
	ctrl_cpu0 &= (~CPU_IO);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(IO_BITMAP_A, (u64)io_bitmap_a);
	vmcs_write(IO_BITMAP_B, (u64)io_bitmap_b);
}

static void iobmp_main()
{
	// stage 0, test IO pass
	set_stage(0);
	inb(0x5000);
	outb(0x0, 0x5000);
	if (stage != 0)
		report("I/O bitmap - I/O pass", 0);
	else
		report("I/O bitmap - I/O pass", 1);
	// test IO width, in/out
	((u8 *)io_bitmap_a)[0] = 0xFF;
	set_stage(2);
	inb(0x0);
	if (stage != 3)
		report("I/O bitmap - trap in", 0);
	else
		report("I/O bitmap - trap in", 1);
	set_stage(3);
	outw(0x0, 0x0);
	if (stage != 4)
		report("I/O bitmap - trap out", 0);
	else
		report("I/O bitmap - trap out", 1);
	set_stage(4);
	inl(0x0);
	if (stage != 5)
		report("I/O bitmap - I/O width, long", 0);
	// test low/high IO port
	set_stage(5);
	((u8 *)io_bitmap_a)[0x5000 / 8] = (1 << (0x5000 % 8));
	inb(0x5000);
	if (stage == 6)
		report("I/O bitmap - I/O port, low part", 1);
	else
		report("I/O bitmap - I/O port, low part", 0);
	set_stage(6);
	((u8 *)io_bitmap_b)[0x1000 / 8] = (1 << (0x1000 % 8));
	inb(0x9000);
	if (stage == 7)
		report("I/O bitmap - I/O port, high part", 1);
	else
		report("I/O bitmap - I/O port, high part", 0);
	// test partial pass
	set_stage(7);
	inl(0x4FFF);
	if (stage == 8)
		report("I/O bitmap - partial pass", 1);
	else
		report("I/O bitmap - partial pass", 0);
	// test overrun
	set_stage(8);
	memset(io_bitmap_a, 0x0, PAGE_SIZE);
	memset(io_bitmap_b, 0x0, PAGE_SIZE);
	inl(0xFFFF);
	if (stage == 9)
		report("I/O bitmap - overrun", 1);
	else
		report("I/O bitmap - overrun", 0);
	
	return;
}

static int iobmp_exit_handler()
{
	u64 guest_rip;
	ulong reason, exit_qual;
	u32 insn_len;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (reason) {
	case VMX_IO:
		switch (stage) {
		case 2:
			if ((exit_qual & VMX_IO_SIZE_MASK) != _VMX_IO_BYTE)
				report("I/O bitmap - I/O width, byte", 0);
			else
				report("I/O bitmap - I/O width, byte", 1);
			if (!(exit_qual & VMX_IO_IN))
				report("I/O bitmap - I/O direction, in", 0);
			else
				report("I/O bitmap - I/O direction, in", 1);
			set_stage(stage + 1);
			break;
		case 3:
			if ((exit_qual & VMX_IO_SIZE_MASK) != _VMX_IO_WORD)
				report("I/O bitmap - I/O width, word", 0);
			else
				report("I/O bitmap - I/O width, word", 1);
			if (!(exit_qual & VMX_IO_IN))
				report("I/O bitmap - I/O direction, out", 1);
			else
				report("I/O bitmap - I/O direction, out", 0);
			set_stage(stage + 1);
			break;
		case 4:
			if ((exit_qual & VMX_IO_SIZE_MASK) != _VMX_IO_LONG)
				report("I/O bitmap - I/O width, long", 0);
			else
				report("I/O bitmap - I/O width, long", 1);
			set_stage(stage + 1);
			break;
		case 5:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x5000)
				set_stage(stage + 1);
			break;
		case 6:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x9000)
				set_stage(stage + 1);
			break;
		case 7:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0x4FFF)
				set_stage(stage + 1);
			break;
		case 8:
			if (((exit_qual & VMX_IO_PORT_MASK) >> VMX_IO_PORT_SHIFT) == 0xFFFF)
				set_stage(stage + 1);
			break;
		case 0:
		case 1:
			set_stage(stage + 1);
		default:
			// Should not reach here
			break;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	default:
		printf("guest_rip = 0x%llx\n", guest_rip);
		printf("\tERROR : Undefined exit reason, reason = %d.\n", reason);
		break;
	}
	return VMX_TEST_VMEXIT;
}

#define INSN_CPU0		0
#define INSN_CPU1		1
#define INSN_ALWAYS_TRAP	2
#define INSN_NEVER_TRAP		3

#define FIELD_EXIT_QUAL		0
#define FIELD_INSN_INFO		1

asm(
	"insn_hlt: hlt;ret\n\t"
	"insn_invlpg: invlpg 0x12345678;ret\n\t"
	"insn_mwait: mwait;ret\n\t"
	"insn_rdpmc: rdpmc;ret\n\t"
	"insn_rdtsc: rdtsc;ret\n\t"
	"insn_monitor: monitor;ret\n\t"
	"insn_pause: pause;ret\n\t"
	"insn_wbinvd: wbinvd;ret\n\t"
	"insn_cpuid: cpuid;ret\n\t"
	"insn_invd: invd;ret\n\t"
);
extern void insn_hlt();
extern void insn_invlpg();
extern void insn_mwait();
extern void insn_rdpmc();
extern void insn_rdtsc();
extern void insn_monitor();
extern void insn_pause();
extern void insn_wbinvd();
extern void insn_cpuid();
extern void insn_invd();

u32 cur_insn;

struct insn_table {
	const char *name;
	u32 flag;
	void (*insn_func)();
	u32 type;
	u32 reason;
	ulong exit_qual;
	u32 insn_info;
	// Use FIELD_EXIT_QUAL and FIELD_INSN_INFO to efines
	// which field need to be tested, reason is always tested
	u32 test_field;
};

static struct insn_table insn_table[] = {
	// Flags for Primary Processor-Based VM-Execution Controls
	{"HLT",  CPU_HLT, insn_hlt, INSN_CPU0, 12, 0, 0, 0},
	{"INVLPG", CPU_INVLPG, insn_invlpg, INSN_CPU0, 14,
		0x12345678, 0, FIELD_EXIT_QUAL},
	{"MWAIT", CPU_MWAIT, insn_mwait, INSN_CPU0, 36, 0, 0, 0},
	{"RDPMC", CPU_RDPMC, insn_rdpmc, INSN_CPU0, 15, 0, 0, 0},
	{"RDTSC", CPU_RDTSC, insn_rdtsc, INSN_CPU0, 16, 0, 0, 0},
	{"MONITOR", CPU_MONITOR, insn_monitor, INSN_CPU0, 39, 0, 0, 0},
	{"PAUSE", CPU_PAUSE, insn_pause, INSN_CPU0, 40, 0, 0, 0},
	// Flags for Secondary Processor-Based VM-Execution Controls
	{"WBINVD", CPU_WBINVD, insn_wbinvd, INSN_CPU1, 54, 0, 0, 0},
	// Instructions always trap
	{"CPUID", 0, insn_cpuid, INSN_ALWAYS_TRAP, 10, 0, 0, 0},
	{"INVD", 0, insn_invd, INSN_ALWAYS_TRAP, 13, 0, 0, 0},
	// Instructions never trap
	{NULL},
};

static void insn_intercept_init()
{
	u32 ctrl_cpu[2];

	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu[0] |= CPU_HLT | CPU_INVLPG | CPU_MWAIT | CPU_RDPMC | CPU_RDTSC |
		CPU_MONITOR | CPU_PAUSE | CPU_SECONDARY;
	ctrl_cpu[0] &= ctrl_cpu_rev[0].clr;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	ctrl_cpu[1] = vmcs_read(CPU_EXEC_CTRL1);
	ctrl_cpu[1] |= CPU_WBINVD | CPU_RDRAND;
	ctrl_cpu[1] &= ctrl_cpu_rev[1].clr;
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
}

static void insn_intercept_main()
{
	cur_insn = 0;
	while(insn_table[cur_insn].name != NULL) {
		set_stage(cur_insn);
		if ((insn_table[cur_insn].type == INSN_CPU0
			&& !(ctrl_cpu_rev[0].clr & insn_table[cur_insn].flag))
			|| (insn_table[cur_insn].type == INSN_CPU1
			&& !(ctrl_cpu_rev[1].clr & insn_table[cur_insn].flag))) {
			printf("\tCPU_CTRL1.CPU_%s is not supported.\n",
				insn_table[cur_insn].name);
			continue;
		}
		insn_table[cur_insn].insn_func();
		switch (insn_table[cur_insn].type) {
		case INSN_CPU0:
		case INSN_CPU1:
		case INSN_ALWAYS_TRAP:
			if (stage != cur_insn + 1)
				report(insn_table[cur_insn].name, 0);
			else
				report(insn_table[cur_insn].name, 1);
			break;
		case INSN_NEVER_TRAP:
			if (stage == cur_insn + 1)
				report(insn_table[cur_insn].name, 0);
			else
				report(insn_table[cur_insn].name, 1);
			break;
		}
		cur_insn ++;
	}
}

static int insn_intercept_exit_handler()
{
	u64 guest_rip;
	u32 reason;
	ulong exit_qual;
	u32 insn_len;
	u32 insn_info;
	bool pass;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	insn_len = vmcs_read(EXI_INST_LEN);
	insn_info = vmcs_read(EXI_INST_INFO);
	pass = (cur_insn == get_stage()) &&
			insn_table[cur_insn].reason == reason;
	if (insn_table[cur_insn].test_field & FIELD_EXIT_QUAL)
		pass = pass && insn_table[cur_insn].exit_qual == exit_qual;
	if (insn_table[cur_insn].test_field & FIELD_INSN_INFO)
		pass = pass && insn_table[cur_insn].insn_info == insn_info;
	if (pass)
		set_stage(stage + 1);
	vmcs_write(GUEST_RIP, guest_rip + insn_len);
	return VMX_TEST_RESUME;
}


static int setup_ept()
{
	int support_2m;
	unsigned long end_of_memory;

	if (!(ept_vpid.val & EPT_CAP_UC) &&
			!(ept_vpid.val & EPT_CAP_WB)) {
		printf("\tEPT paging-structure memory type "
				"UC&WB are not supported\n");
		return 1;
	}
	if (ept_vpid.val & EPT_CAP_UC)
		eptp = EPT_MEM_TYPE_UC;
	else
		eptp = EPT_MEM_TYPE_WB;
	if (!(ept_vpid.val & EPT_CAP_PWL4)) {
		printf("\tPWL4 is not supported\n");
		return 1;
	}
	eptp |= (3 << EPTP_PG_WALK_LEN_SHIFT);
	pml4 = alloc_page();
	memset(pml4, 0, PAGE_SIZE);
	eptp |= virt_to_phys(pml4);
	vmcs_write(EPTP, eptp);
	support_2m = !!(ept_vpid.val & EPT_CAP_2M_PAGE);
	end_of_memory = fwcfg_get_u64(FW_CFG_RAM_SIZE);
	if (end_of_memory < (1ul << 32))
		end_of_memory = (1ul << 32);
	if (setup_ept_range(pml4, 0, end_of_memory,
			0, support_2m, EPT_WA | EPT_RA | EPT_EA)) {
		printf("\tSet ept tables failed.\n");
		return 1;
	}
	return 0;
}

static void ept_init()
{
	u32 ctrl_cpu[2];

	init_fail = false;
	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu[1] = vmcs_read(CPU_EXEC_CTRL1);
	ctrl_cpu[0] = (ctrl_cpu[0] | CPU_SECONDARY)
		& ctrl_cpu_rev[0].clr;
	ctrl_cpu[1] = (ctrl_cpu[1] | CPU_EPT)
		& ctrl_cpu_rev[1].clr;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	if (setup_ept())
		init_fail = true;
	data_page1 = alloc_page();
	data_page2 = alloc_page();
	memset(data_page1, 0x0, PAGE_SIZE);
	memset(data_page2, 0x0, PAGE_SIZE);
	*((u32 *)data_page1) = MAGIC_VAL_1;
	*((u32 *)data_page2) = MAGIC_VAL_2;
	install_ept(pml4, (unsigned long)data_page1, (unsigned long)data_page2,
			EPT_RA | EPT_WA | EPT_EA);
}

static void ept_main()
{
	if (init_fail)
		return;
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY)
		&& !(ctrl_cpu_rev[1].clr & CPU_EPT)) {
		printf("\tEPT is not supported");
		return;
	}
	set_stage(0);
	if (*((u32 *)data_page2) != MAGIC_VAL_1 &&
			*((u32 *)data_page1) != MAGIC_VAL_1)
		report("EPT basic framework - read", 0);
	else {
		*((u32 *)data_page2) = MAGIC_VAL_3;
		vmcall();
		if (get_stage() == 1) {
			if (*((u32 *)data_page1) == MAGIC_VAL_3 &&
					*((u32 *)data_page2) == MAGIC_VAL_2)
				report("EPT basic framework", 1);
			else
				report("EPT basic framework - remap", 1);
		}
	}
	// Test EPT Misconfigurations
	set_stage(1);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	if (get_stage() != 2) {
		report("EPT misconfigurations", 0);
		goto t1;
	}
	set_stage(2);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	if (get_stage() != 3) {
		report("EPT misconfigurations", 0);
		goto t1;
	}
	report("EPT misconfigurations", 1);
t1:
	// Test EPT violation
	set_stage(3);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_1;
	if (get_stage() == 4)
		report("EPT violation - page permission", 1);
	else
		report("EPT violation - page permission", 0);
	// Violation caused by EPT paging structure
	set_stage(4);
	vmcall();
	*((u32 *)data_page1) = MAGIC_VAL_2;
	if (get_stage() == 5)
		report("EPT violation - paging structure", 1);
	else
		report("EPT violation - paging structure", 0);
	return;
}

static int ept_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	u32 exit_qual;
	static unsigned long data_page1_pte, data_page1_pte_pte;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	exit_qual = vmcs_read(EXI_QUALIFICATION);
	switch (reason) {
	case VMX_VMCALL:
		switch (get_stage()) {
		case 0:
			if (*((u32 *)data_page1) == MAGIC_VAL_3 &&
					*((u32 *)data_page2) == MAGIC_VAL_2) {
				set_stage(get_stage() + 1);
				install_ept(pml4, (unsigned long)data_page2,
						(unsigned long)data_page2,
						EPT_RA | EPT_WA | EPT_EA);
			} else
				report("EPT basic framework - write\n", 0);
			break;
		case 1:
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1, EPT_WA);
			invept(INVEPT_SINGLE, eptp);
			break;
		case 2:
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1,
 				EPT_RA | EPT_WA | EPT_EA |
 				(2 << EPT_MEM_TYPE_SHIFT));
			invept(INVEPT_SINGLE, eptp);
			break;
		case 3:
			data_page1_pte = get_ept_pte(pml4,
				(unsigned long)data_page1, 1);
			set_ept_pte(pml4, (unsigned long)data_page1, 
				1, data_page1_pte & (~EPT_PRESENT));
			invept(INVEPT_SINGLE, eptp);
			break;
		case 4:
			data_page1_pte = get_ept_pte(pml4,
				(unsigned long)data_page1, 2);
			data_page1_pte &= PAGE_MASK;
			data_page1_pte_pte = get_ept_pte(pml4, data_page1_pte, 2);
			set_ept_pte(pml4, data_page1_pte, 2,
				data_page1_pte_pte & (~EPT_PRESENT));
			invept(INVEPT_SINGLE, eptp);
			break;
		// Should not reach here
		default:
			printf("ERROR - unknown stage, %d.\n", get_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		return VMX_TEST_RESUME;
	case VMX_EPT_MISCONFIG:
		switch (get_stage()) {
		case 1:
		case 2:
			set_stage(get_stage() + 1);
			install_ept(pml4, (unsigned long)data_page1,
 				(unsigned long)data_page1,
 				EPT_RA | EPT_WA | EPT_EA);
			invept(INVEPT_SINGLE, eptp);
			break;
		// Should not reach here
		default:
			printf("ERROR - unknown stage, %d.\n", get_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	case VMX_EPT_VIOLATION:
		switch(get_stage()) {
		case 3:
			if (exit_qual == (EPT_VLT_WR | EPT_VLT_LADDR_VLD |
					EPT_VLT_PADDR))
				set_stage(get_stage() + 1);
			set_ept_pte(pml4, (unsigned long)data_page1, 
				1, data_page1_pte | (EPT_PRESENT));
			invept(INVEPT_SINGLE, eptp);
			break;
		case 4:
			if (exit_qual == (EPT_VLT_RD | EPT_VLT_LADDR_VLD))
				set_stage(get_stage() + 1);
			set_ept_pte(pml4, data_page1_pte, 2,
				data_page1_pte_pte | (EPT_PRESENT));
			invept(INVEPT_SINGLE, eptp);
			break;
		default:
			// Should not reach here
			printf("ERROR : unknown stage, %d\n", get_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	default:
		printf("Unknown exit reason, %d\n", reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static int reset_vmstat(struct vmcs *vmcs)
{
	if (vmcs_clear(current->vmcs)) {
		printf("\tERROR : %s : vmcs_clear failed.\n", __func__);
		return -1;
	}
	if (make_vmcs_current(current->vmcs)) {
		printf("\tERROR : %s : make_vmcs_current failed.\n", __func__);
		return -1;
	}
	launched = 0;
	return 0;
}

static int vmentry_vmcs_absence()
{
	vmcs_clear(current->vmcs);
	return 0;
}

static int vmentry_vmlaunch_err()
{
	launched = 0;
	return 0;
}

static int vmentry_vmresume_err()
{
	if (reset_vmstat(current->vmcs))
		return -1;
	launched = 1;
	return 0;
}

static int vmentry_pin_ctrl()
{
	vmcs_write(PIN_CONTROLS, ~(ctrl_pin_rev.clr));
	return 0;
}

static int vmentry_cpu0_ctrl()
{
	vmcs_write(CPU_EXEC_CTRL0, ~(ctrl_cpu_rev[0].clr));
	return 0;
}

static int vmentry_cpu1_ctrl()
{
	u32 ctrl_cpu[2];
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0] | CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, ~(ctrl_cpu_rev[1].clr));
	return 0;
}

static int vmentry_cr3_target_count()
{
	vmcs_write(CR3_TARGET_COUNT, 5);
	return 0;
}

static int vmentry_iobmp_invalid1()
{
	u32 ctrl_cpu0;
	if (!(ctrl_cpu_rev[0].clr & CPU_IO_BITMAP)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_IO_BITMAP;
	ctrl_cpu0 &= (~CPU_IO);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(IO_BITMAP_A, 0x1);
	vmcs_write(IO_BITMAP_B, 0x1);
	return 0;
}

static int vmentry_iobmp_invalid2()
{
	u32 ctrl_cpu0;
	if (!(ctrl_cpu_rev[0].clr & CPU_IO_BITMAP)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_IO_BITMAP;
	ctrl_cpu0 &= (~CPU_IO);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(IO_BITMAP_A, 1ull << (phy_addr_width + 1));
	vmcs_write(IO_BITMAP_B, 1ull << (phy_addr_width + 1));
	return 0;
}

static int vmentry_msrbmp_invalid1()
{
	u32 ctrl_cpu0;
	if (!(ctrl_cpu_rev[0].clr & CPU_MSR_BITMAP)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_MSR_BITMAP;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(MSR_BITMAP, 0x1);
	return 0;
}

static int vmentry_msrbmp_invalid2()
{
	u32 ctrl_cpu0;
	if (!(ctrl_cpu_rev[0].clr & CPU_MSR_BITMAP)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu0 = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu0 |= CPU_MSR_BITMAP;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu0);
	vmcs_write(MSR_BITMAP, 1ull << (phy_addr_width + 1));
	return 0;
}

static int vmentry_nmi()
{
	u32 ctrl_pin;
	if (!(ctrl_pin_rev.clr & PIN_NMI) ||
			!(ctrl_pin_rev.clr & PIN_VIRT_NMI)) {
		test_success = true;
		return 0;
	}
	ctrl_pin = vmcs_read(PIN_CONTROLS);
	ctrl_pin &= ~(PIN_NMI);
	ctrl_pin |= PIN_VIRT_NMI;
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	return 0;
}

static int vmentry_apic_invalid1()
{
	u32 ctrl_cpu[2];
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
			!(ctrl_cpu_rev[1].clr & CPU_VIRT_APIC)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu[1] = vmcs_read(CPU_EXEC_CTRL1);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0] | CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1] | CPU_VIRT_APIC);
	vmcs_write(APIC_ACCS_ADDR, 0x1);
	return 0;
}

static int vmentry_apic_invalid2()
{
	u32 ctrl_cpu[2];
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
			!(ctrl_cpu_rev[1].clr & CPU_VIRT_APIC)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 0;
	}
	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu[1] = vmcs_read(CPU_EXEC_CTRL1);
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0] | CPU_SECONDARY);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1] | CPU_VIRT_APIC);
	vmcs_write(APIC_ACCS_ADDR, 1ull << (phy_addr_width + 1));
	return 0;
}


static int vmentry_init_eptp()
{
	u32 ctrl_cpu[2];
	if (!(ctrl_cpu_rev[0].clr & CPU_SECONDARY) ||
			!(ctrl_cpu_rev[1].clr & CPU_EPT)) {
		printf("\t%s : Features are not supported for nested.\n", __func__);
		test_success = true;
		return 1;
	}
	ctrl_cpu[0] = vmcs_read(CPU_EXEC_CTRL0);
	ctrl_cpu[1] = vmcs_read(CPU_EXEC_CTRL1);
	ctrl_cpu[0] = ctrl_cpu[0] | CPU_SECONDARY;
	ctrl_cpu[1] = ctrl_cpu[1] | CPU_EPT;
	vmcs_write(CPU_EXEC_CTRL0, ctrl_cpu[0]);
	vmcs_write(CPU_EXEC_CTRL1, ctrl_cpu[1]);
	if (setup_ept())
		return 1;
	return 0;
}

static int vmentry_eptp_memtype()
{
	if (vmentry_init_eptp())
		return 0;
	eptp &= (~EPT_MEM_TYPE_MASK);
	eptp |= EPT_MEM_TYPE_WT;
	vmcs_write(EPTP, eptp);
	return 0;
}

static int vmentry_eptp_pwl()
{
	if (vmentry_init_eptp())
		return 0;
	eptp &= (~EPTP_PG_WALK_LEN_MASK);
	vmcs_write(EPTP, eptp);
	return 0;
}

static int vmentry_eptp_rsv_bits1()
{
	if (vmentry_init_eptp())
		return 0;
	eptp |= (1ull << 8);
	vmcs_write(EPTP, eptp);
	return 0;
}

static int vmentry_eptp_rsv_bits2()
{
	if (vmentry_init_eptp())
		return 0;
	eptp &= ~(PAGE_MASK);
	eptp |= (1ull << (phy_addr_width + 1)) & PAGE_MASK;
	vmcs_write(EPTP, eptp);
	return 0;
}


static int vmentry_exit_ctrl()
{
	vmcs_write(EXI_CONTROLS, ~(ctrl_exit_rev.clr));
	return 0;
}

static int vmentry_preempt()
{
	u32 ctrl_pin, ctrl_exit;
	ctrl_pin = vmcs_read(PIN_CONTROLS);
	ctrl_exit = vmcs_read(EXI_CONTROLS);
	ctrl_pin &= (~PIN_PREEMPT);
	ctrl_exit |= EXI_SAVE_PREEMPT;
	vmcs_write(PIN_CONTROLS, ctrl_pin);
	vmcs_write(EXI_CONTROLS, ctrl_exit);
	return 0;
}

static int vmentry_ent_ctrl()
{
	vmcs_write(ENT_CONTROLS, ~(ctrl_enter_rev.clr));
	return 0;
}

static int vmentry_ent_smm()
{
	u32 ctrl_enter;
	ctrl_enter = vmcs_read(ENT_CONTROLS);
	ctrl_enter |= ENT_ENT_SMM;
	vmcs_write(ENT_CONTROLS, ctrl_enter);
	return 0;
}

static int vmentry_deatv_dm()
{
	u32 ctrl_enter;
	ctrl_enter = vmcs_read(ENT_CONTROLS);
	ctrl_enter |= ENT_DEATV_DM;
	vmcs_write(ENT_CONTROLS, ctrl_enter);
	return 0;
}

static int vmentry_invalid_cr0()
{
	u32 host_cr0;
	host_cr0 = vmcs_read(HOST_CR0);
	host_cr0 &= ~X86_CR0_PE;
	vmcs_write(HOST_CR0, host_cr0);
	return 0;
}

static int vmentry_invalid_cr4()
{
	u32 host_cr4;
	host_cr4 = vmcs_read(HOST_CR4);
	host_cr4 &= ~X86_CR4_VMXE;
	vmcs_write(HOST_CR4, host_cr4);
	return 0;
}

static int vmentry_invalid_cr3()
{
	u32 host_cr3;
	host_cr3 = vmcs_read(HOST_CR3);
	host_cr3 |= (1ull << 63);
	vmcs_write(HOST_CR3, host_cr3);
	return 0;
}

static int vmentry_sysenter_esp_addr()
{
	vmcs_write(HOST_SYSENTER_ESP, ~0ull);
	return 0;
}

static int vmentry_sysenter_eip_addr()
{
	vmcs_write(HOST_SYSENTER_EIP, ~0ull);
	return 0;
}

static int vmentry_host_PAT()
{
	u32 ctrl_exit;
	ctrl_exit = vmcs_read(EXI_CONTROLS);
	ctrl_exit |= EXI_LOAD_PAT;
	vmcs_write(EXI_CONTROLS, ctrl_exit);
	vmcs_write(HOST_PAT, 0x3);
	return 0;
}

static int vmentry_host_EFER1()
{
	u32 ctrl_exit;
	ctrl_exit = vmcs_read(EXI_CONTROLS);
	ctrl_exit |= EXI_LOAD_EFER;
	vmcs_write(EXI_CONTROLS, ctrl_exit);
	vmcs_write(HOST_EFER, 0x2);
	return 0;
}

static int vmentry_host_EFER2()
{
	u32 ctrl_exit;
	u64 host_efer;
	ctrl_exit = vmcs_read(EXI_CONTROLS);
	ctrl_exit |= EXI_LOAD_EFER;
	vmcs_write(EXI_CONTROLS, ctrl_exit);
	host_efer = rdmsr(MSR_EFER);
	vmcs_write(HOST_EFER, host_efer ^ EFER_LMA);
	return 0;
}

static int vmentry_cs_rpl()
{
	u16 host_sel_cs;
	host_sel_cs = vmcs_read(HOST_SEL_CS);
	vmcs_write(HOST_SEL_CS, host_sel_cs | 1);
	return 0;
}

static int vmentry_tr_rpl()
{
	u16 host_sel_tr;
	host_sel_tr = vmcs_read(HOST_SEL_TR);
	vmcs_write(HOST_SEL_CS, host_sel_tr | 1);
	return 0;
}

static int vmentry_cs_ti()
{
	u16 host_sel_cs;
	host_sel_cs = vmcs_read(HOST_SEL_CS);
	vmcs_write(HOST_SEL_CS, host_sel_cs | (1 << 2));
	return 0;
}

static int vmentry_tr_ti()
{
	u16 host_sel_tr;
	host_sel_tr = vmcs_read(HOST_SEL_TR);
	vmcs_write(HOST_SEL_CS, host_sel_tr | (1 << 2));
	return 0;
}

static int vmentry_cs_0()
{
	vmcs_write(HOST_SEL_CS, 0);
	return 0;
}

static int vmentry_tr_0()
{
	vmcs_write(HOST_SEL_TR, 0);
	return 0;
}

static int vmentry_addr_fs()
{
	vmcs_write(HOST_BASE_FS, ~0ull);
	return 0;
}

static int vmentry_addr_gs()
{
	vmcs_write(HOST_BASE_GS, ~0ull);
	return 0;
}

static int vmentry_addr_gdtr()
{
	vmcs_write(HOST_BASE_GDTR, ~0ull);
	return 0;
}

static int vmentry_addr_idtr()
{
	vmcs_write(HOST_BASE_IDTR, ~0ull);
	return 0;
}

static int vmentry_addr_tr()
{
	vmcs_write(HOST_BASE_TR, ~0ull);
	return 0;
}

static int vmentry_hds()
{
	u32 ctrl_exit;
	ctrl_exit = vmcs_read(EXI_CONTROLS);
	vmcs_write(EXI_CONTROLS, ctrl_exit & ~(EXI_HOST_64));
	return 0;
}

static int vmentry_exi_host_64_pae()
{
	unsigned long host_cr4;
	u32 ctrl_exit;
	ctrl_exit = vmcs_read(EXI_CONTROLS);
	vmcs_write(EXI_CONTROLS, ctrl_exit | EXI_HOST_64);
	host_cr4 = vmcs_read(HOST_CR4);
	vmcs_write(HOST_CR4, host_cr4 & ~(X86_CR4_PAE));
	return 0;
}

static int vmentry_exi_host_rip()
{
	vmcs_write(HOST_RIP, ~0ull);
	return 0;
}

#define	VMENTRY_INIT		0
#define	VMENTRY_TESTS		1
#define VMENTRY_RESET		2

struct vmentry_check_table {
	const char *name;
	u64 flags;
	int (*exit_handler)();
};

/*
 * NOTE:
 * Unsupported nested features are not tested here, which includes:
 *	shadow VMCS realted features
 *	TPR related features
 *	process posted interrupts
 *	VPID related features
 *	virtual-interrupt delivery
 *	virtualize x2APIC mode
 *	NMI-window exiting
 *	unrestricted guest
 *	VMFUNC related features
 *	EPT-violation #VE
 *	vmexit/vmenter MSR store/load
 *	vmenter event injection (better checked in event injection suite)
 *	"load IA32_PERF_GLOBAL_CTRL" VM-exit control related
 */
static struct vmentry_check_table vmentry_cases[] = {
	/*
	 * Part I : Test basic vmentry checks
	 * This part tests restrictions in Intel SDM 26.1
	 * For the restriction of framework, we only test 3, 4 and 5 (except 5.a)
	 */
	{"No current VMCS vmenter", X86_EFLAGS_CF, vmentry_vmcs_absence},
	{"VMLAUNCH with state not clear", X86_EFLAGS_ZF, vmentry_vmlaunch_err},
	{"VMRESUME with state not launched", X86_EFLAGS_ZF, vmentry_vmresume_err},

	/* Part II : Test checks on vmx controls and host state */
	/* II.1 Checks on VMX Controls */
	// 26.2.1.1 VM-Execution Control Fields
	{"Reserved bits in PIN_CONTROLS field", X86_EFLAGS_ZF, vmentry_pin_ctrl},
	{"Reserved bits in primary CPU CONTROLS field", X86_EFLAGS_ZF, vmentry_cpu0_ctrl},
	{"Reserved bits in secondary CPU CONTROLS field", X86_EFLAGS_ZF, vmentry_cpu1_ctrl},
	{"CR3 target count greater than 4", X86_EFLAGS_ZF, vmentry_cr3_target_count},
	{"I/O bitmap address invalid (aligned)", X86_EFLAGS_ZF, vmentry_iobmp_invalid1},
	{"I/O bitmap address invalid (exceed)", X86_EFLAGS_ZF, vmentry_iobmp_invalid2},
	{"MSR bitmap address invalid (aligned)", X86_EFLAGS_ZF, vmentry_msrbmp_invalid1},
	{"MSR bitmap address invalid (exceed)", X86_EFLAGS_ZF, vmentry_msrbmp_invalid2},
	{"Consistency of NMI exiting and virtual NMIs", X86_EFLAGS_ZF, vmentry_nmi},
	{"APIC-accesses address invalid (aligned)", X86_EFLAGS_ZF, vmentry_apic_invalid1},
	{"APIC-accesses address invalid (exceed)", X86_EFLAGS_ZF, vmentry_apic_invalid2},
	{"EPTP memory type", X86_EFLAGS_ZF, vmentry_eptp_memtype},
	{"EPTP page walk length", X86_EFLAGS_ZF, vmentry_eptp_pwl},
	{"EPTP page reserved bits (11:7)", X86_EFLAGS_ZF, vmentry_eptp_rsv_bits1},
//	{"EPTP page reserved bits (63:N)", X86_EFLAGS_ZF, vmentry_eptp_rsv_bits2},
	// 26.2.1.2 VM-Exit Control Fields
	{"Reserved bits in EXI_CONTROLS field", X86_EFLAGS_ZF, vmentry_exit_ctrl},
	{"Consistency of VMX-preemption timer (activate and save)",
		X86_EFLAGS_ZF, vmentry_preempt},
	// 26.2.1.3 VM-Entry Control Fields
	{"Reserved bits in ENT_CONTROLS field", X86_EFLAGS_ZF, vmentry_ent_ctrl},
	{"Entry to SMM with processor not in SMM", X86_EFLAGS_ZF, vmentry_ent_smm},
	{"Deactivate dual-monitor treatment with processor not in SMM",
		X86_EFLAGS_ZF, vmentry_deatv_dm},
	// 26.2.2 Checks on Host Control Registers and MSRs
	{"Invalid bits in host CR0", X86_EFLAGS_ZF, vmentry_invalid_cr0},
	{"Invalid bits in host CR4", X86_EFLAGS_ZF, vmentry_invalid_cr4},
	{"Invalid bits in host CR3", X86_EFLAGS_ZF, vmentry_invalid_cr3},
	{"Invalid host sysenter esp addr", X86_EFLAGS_ZF, vmentry_sysenter_esp_addr},
	{"Invalid host sysenter eip addr", X86_EFLAGS_ZF, vmentry_sysenter_eip_addr},
//	{"Invalid host PAT", X86_EFLAGS_ZF, vmentry_host_PAT},
//	{"Invalid host EFER - bits reserved", X86_EFLAGS_ZF, vmentry_host_EFER1},
//	{"Invalid host EFER - LMA & LME", X86_EFLAGS_ZF, vmentry_host_EFER2},
	// 26.2.3 Checks on Host Segment and Descriptor-Table Registers
//	{"Invalid CS selector field - RPL", X86_EFLAGS_ZF, vmentry_cs_rpl},
//	{"Invalid TR selector field - RPL", X86_EFLAGS_ZF, vmentry_tr_rpl},
	{"Invalid CS selector field - TI flag", X86_EFLAGS_ZF, vmentry_cs_ti},
	{"Invalid TR selector field - TI flag", X86_EFLAGS_ZF, vmentry_tr_ti},
	{"Invalid CS selector field - 0000H", X86_EFLAGS_ZF, vmentry_cs_0},
	{"Invalid TR selector field - 0000H", X86_EFLAGS_ZF, vmentry_tr_0},
	{"Invalid base address of FS", X86_EFLAGS_ZF, vmentry_addr_fs},
	{"Invalid base address of GS", X86_EFLAGS_ZF, vmentry_addr_gs},
	{"Invalid base address of GDTR", X86_EFLAGS_ZF, vmentry_addr_gdtr},
	{"Invalid base address of IDTR", X86_EFLAGS_ZF, vmentry_addr_idtr},
	{"Invalid base address of TR", X86_EFLAGS_ZF, vmentry_addr_tr},
	//26.2.4 Checks Related to Address-Space Size
//	{"64bit host with EXI_HOST_64 unset", X86_EFLAGS_ZF, vmentry_hds},
	{"Consistency of EXI_HOST_64 and CR4.PAE", X86_EFLAGS_ZF, vmentry_exi_host_64_pae},
//	{"64bit host with invalid host RIP", X86_EFLAGS_ZF, vmentry_exi_host_rip},
	{NULL, 0},
};

struct vmcs *vmentry_check_vmcs;

static void vmentry_check_main()
{
	set_stage(VMENTRY_INIT);
	vmcall();
	cur_test = 0;
	while (vmentry_cases[cur_test].name != NULL) {
		test_success = false;
		set_stage(VMENTRY_TESTS);
		vmcall();
		if (!test_success) {
			set_stage(VMENTRY_RESET);
			vmcall();
			report(vmentry_cases[cur_test].name, 0);
		}
		cur_test++;
	}
	return;
}

static int vmentry_check_exit_handler()
{
	u64 guest_rip;
	ulong reason;
	u32 insn_len;
	struct cpuid r;

	guest_rip = vmcs_read(GUEST_RIP);
	reason = vmcs_read(EXI_REASON) & 0xff;
	insn_len = vmcs_read(EXI_INST_LEN);
	switch (reason) {
	case VMX_VMCALL:
		vmcs_write(GUEST_RIP, guest_rip + insn_len);
		switch (get_stage()) {
		case VMENTRY_INIT:
			/*
			 * In VMENTRY_SAVE_VMCS stage, we should save current->vmcs
			 * to vmentry_check_vmcs used by entry_failed_handler.
			 */
			vmentry_check_vmcs = alloc_page();
			vmcs_clear(current->vmcs);
			memcpy(vmentry_check_vmcs, current->vmcs, PAGE_SIZE);
			make_vmcs_current(current->vmcs);
			launched = 0;
			// Get physical address width
			r = cpuid(0x80000008);
			phy_addr_width = r.a & 0xFF;
			break;
		case VMENTRY_TESTS:
			// Write current RIP to vmentry_check_vmcs
			make_vmcs_current(vmentry_check_vmcs);
			vmcs_write(GUEST_RIP, guest_rip + insn_len);
			vmcs_clear(vmentry_check_vmcs);
			make_vmcs_current(current->vmcs);
			if (vmentry_cases[cur_test].exit_handler())
				return VMX_TEST_VMEXIT;
			break;
		case VMENTRY_RESET:
			memcpy(current->vmcs, vmentry_check_vmcs, PAGE_SIZE);
			if (reset_vmstat(current->vmcs))
				return VMX_TEST_VMEXIT;
			vmcs_write(GUEST_RIP, guest_rip + insn_len);
			break;
		// Should not reach here
		default:
			printf("\tERROR : Undefined stage, %d\n", get_stage());
			print_vmexit_info();
			return VMX_TEST_VMEXIT;
		}
		return VMX_TEST_RESUME;
	default:
		printf("Unknown exit reason, %d\n", reason);
		print_vmexit_info();
	}
	return VMX_TEST_VMEXIT;
}

static int vmentry_check_entry_failed_handler()
{
	if (get_stage() != VMENTRY_TESTS) {
		printf("\tERROR : Unknown stage, %d.\n", get_stage());
		return VMX_TEST_EXIT;
	}
	if (host_rflags & vmentry_cases[cur_test].flags) {
		test_success = true;
		report(vmentry_cases[cur_test].name, 1);
	}
	memcpy(current->vmcs, vmentry_check_vmcs, PAGE_SIZE);
	if (reset_vmstat(current->vmcs))
			return VMX_TEST_VMEXIT;
	return VMX_TEST_RESUME;
}

/* name/init/guest_main/exit_handler/syscall_handler/guest_regs
   basic_* just implement some basic functions */
struct vmx_test vmx_tests[] = {
	{ "null", basic_init, basic_guest_main, basic_exit_handler,
		basic_syscall_handler, basic_entry_failed_handler, {0} },
	{ "vmenter", basic_init, vmenter_main, vmenter_exit_handler,
		basic_syscall_handler, basic_entry_failed_handler, {0} },
	{ "preemption timer", preemption_timer_init, preemption_timer_main,
		preemption_timer_exit_handler, basic_syscall_handler,
		basic_entry_failed_handler, {0} },
	{ "control field PAT", test_ctrl_pat_init, test_ctrl_pat_main,
		test_ctrl_pat_exit_handler, basic_syscall_handler,
		basic_entry_failed_handler, {0} },
	{ "control field EFER", test_ctrl_efer_init, test_ctrl_efer_main,
		test_ctrl_efer_exit_handler, basic_syscall_handler,
		basic_entry_failed_handler, {0} },
	{ "CR shadowing", basic_init, cr_shadowing_main,
		cr_shadowing_exit_handler, basic_syscall_handler,
		basic_entry_failed_handler, {0} },
	{ "I/O bitmap", iobmp_init, iobmp_main, iobmp_exit_handler,
		basic_syscall_handler, basic_entry_failed_handler, {0} },
	{ "instruction intercept", insn_intercept_init, insn_intercept_main,
		insn_intercept_exit_handler, basic_syscall_handler,
		basic_entry_failed_handler, {0} },
	{ "EPT framework", ept_init, ept_main, ept_exit_handler,
		basic_syscall_handler, basic_entry_failed_handler, {0} },
	{ "vmentry check", basic_init, vmentry_check_main,
		vmentry_check_exit_handler, basic_syscall_handler,
		vmentry_check_entry_failed_handler, {0} },
	{ NULL, NULL, NULL, NULL, NULL, NULL, {0} },
};
