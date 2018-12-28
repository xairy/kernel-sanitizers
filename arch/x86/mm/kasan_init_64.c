#define DISABLE_BRANCH_PROFILING
#define pr_fmt(fmt) "kasan: " fmt
#include <linux/bootmem.h>
#include <linux/kasan.h>
#include <linux/kdebug.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern struct range pfn_mapped[E820_X_MAX];

static __init void *early_alloc(size_t size, int nid, bool panic)
{
	if (panic)
		return memblock_virt_alloc_try_nid(size, size,
			__pa(MAX_DMA_ADDRESS), BOOTMEM_ALLOC_ACCESSIBLE, nid);
	else
		return memblock_virt_alloc_try_nid_nopanic(size, size,
			__pa(MAX_DMA_ADDRESS), BOOTMEM_ALLOC_ACCESSIBLE, nid);
}

static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
				      unsigned long end, int nid)
{
	pte_t *pte;

	if (pmd_none(*pmd)) {
		void *p;

		if (boot_cpu_has(X86_FEATURE_PSE) &&
		    ((end - addr) == PMD_SIZE) &&
		    IS_ALIGNED(addr, PMD_SIZE)) {
			p = early_alloc(PMD_SIZE, nid, false);
			if (p && pmd_set_huge(pmd, __pa(p), PAGE_KERNEL))
				return;
			else if (p)
				memblock_free(__pa(p), PMD_SIZE);
		}

		p = early_alloc(PAGE_SIZE, nid, true);
		pmd_populate_kernel(&init_mm, pmd, p);
	}

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t entry;
		void *p;

		if (!pte_none(*pte))
			continue;

		p = early_alloc(PAGE_SIZE, nid, true);
		entry = pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
		set_pte_at(&init_mm, addr, pte, entry);
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void __init kasan_populate_pud(pud_t *pud, unsigned long addr,
				      unsigned long end, int nid)
{
	pmd_t *pmd;
	unsigned long next;

	if (pud_none(*pud)) {
		void *p;

		if (boot_cpu_has(X86_FEATURE_GBPAGES) &&
		    ((end - addr) == PUD_SIZE) &&
		    IS_ALIGNED(addr, PUD_SIZE)) {
			p = early_alloc(PUD_SIZE, nid, false);
			if (p && pud_set_huge(pud, __pa(p), PAGE_KERNEL))
				return;
			else if (p)
				memblock_free(__pa(p), PUD_SIZE);
		}

		p = early_alloc(PAGE_SIZE, nid, true);
		pud_populate(&init_mm, pud, p);
	}

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (!pmd_large(*pmd))
			kasan_populate_pmd(pmd, addr, next, nid);
	} while (pmd++, addr = next, addr != end);
}

static void __init kasan_populate_pgd(pgd_t *pgd, unsigned long addr,
				      unsigned long end, int nid)
{
	pud_t *pud;
	unsigned long next;

	if (pgd_none(*pgd)) {
		void *p = early_alloc(PAGE_SIZE, nid, true);
		pgd_populate(&init_mm, pgd, p);
	}

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (!pud_large(*pud))
			kasan_populate_pud(pud, addr, next, nid);
	} while (pud++, addr = next, addr != end);
}

static void __init kasan_populate_shadow(unsigned long addr, unsigned long end,
					 int nid)
{
	pgd_t *pgd;
	unsigned long next;

	addr = addr & PAGE_MASK;
	end = round_up(end, PAGE_SIZE);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		kasan_populate_pgd(pgd, addr, next, nid);
	} while (pgd++, addr = next, addr != end);
}

static void __init map_range(struct range *range)
{
	unsigned long start;
	unsigned long end;

	start = (unsigned long)kasan_mem_to_shadow(pfn_to_kaddr(range->start));
	end = (unsigned long)kasan_mem_to_shadow(pfn_to_kaddr(range->end));

	kasan_populate_shadow(start, end, early_pfn_to_nid(range->start));
}

static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}

static void __init kasan_map_early_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(kasan_early_shadow_pud)
				| _KERNPG_TABLE);
		start += PGDIR_SIZE;
	}
}

#ifdef CONFIG_KASAN_INLINE
static int kasan_die_handler(struct notifier_block *self,
			     unsigned long val,
			     void *data)
{
	if (val == DIE_GPF) {
		pr_emerg("CONFIG_KASAN_INLINE enabled\n");
		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access\n");
	}
	return NOTIFY_OK;
}

static struct notifier_block kasan_die_notifier = {
	.notifier_call = kasan_die_handler,
};
#endif

void __init kasan_early_init(void)
{
	int i;
	pteval_t pte_val = __pa_nodebug(kasan_early_shadow_page) | __PAGE_KERNEL;
	pmdval_t pmd_val = __pa_nodebug(kasan_early_shadow_pte) | _KERNPG_TABLE;
	pudval_t pud_val = __pa_nodebug(kasan_early_shadow_pmd) | _KERNPG_TABLE;

	for (i = 0; i < PTRS_PER_PTE; i++)
		kasan_early_shadow_pte[i] = __pte(pte_val);

	for (i = 0; i < PTRS_PER_PMD; i++)
		kasan_early_shadow_pmd[i] = __pmd(pmd_val);

	for (i = 0; i < PTRS_PER_PUD; i++)
		kasan_early_shadow_pud[i] = __pud(pud_val);

	kasan_map_early_shadow(early_level4_pgt);
	kasan_map_early_shadow(init_level4_pgt);
}

void __init kasan_init(void)
{
	int i;

#ifdef CONFIG_KASAN_INLINE
	register_die_notifier(&kasan_die_notifier);
#endif

	memcpy(early_level4_pgt, init_level4_pgt, sizeof(early_level4_pgt));
	load_cr3(early_level4_pgt);
	__flush_tlb_all();

	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);

	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
			kasan_mem_to_shadow((void *)PAGE_OFFSET));

	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		map_range(&pfn_mapped[i]);
	}
	kasan_populate_early_shadow(
		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
		kasan_mem_to_shadow((void *)__START_KERNEL_map));

	kasan_populate_shadow((unsigned long)kasan_mem_to_shadow(_stext),
			      (unsigned long)kasan_mem_to_shadow(_end),
			      early_pfn_to_nid(__pa(_stext)));

	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)MODULES_END),
			(void *)KASAN_SHADOW_END);

	load_cr3(init_level4_pgt);
	__flush_tlb_all();

	/*
	 * kasan_early_shadow_page has been used as early shadow memory, thus
	 * it may contain some garbage. Now we can clear and write protect it,
	 * since after the TLB flush no one should write to it.
	 */
	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte_t pte = __pte(__pa(kasan_early_shadow_page) | __PAGE_KERNEL_RO);
		set_pte(&kasan_early_shadow_pte[i], pte);
	}
	/* Flush TLBs again to be sure that write protection applied. */
	__flush_tlb_all();

	init_task.kasan_depth = 0;
	pr_info("KernelAddressSanitizer initialized\n");
}
