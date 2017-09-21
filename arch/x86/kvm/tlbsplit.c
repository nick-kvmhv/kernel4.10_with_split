/*
 * tlbsplit.c
 *
 *  Created on: Dec 28, 2015
 *      Author: nick
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
/*
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
*/
#include <linux/tlbsplit.h>
#include <asm/vmx.h>
#include <linux/debugfs.h>
#include <linux/kvm_host.h>
//#include <linux/gfp.h>
#include "mmu.h"
#include "winntstruct.h"

static int tlbsplit_buffer_size = 0x200 ;
module_param(tlbsplit_buffer_size, int, 0);
MODULE_PARM_DESC(tlbsplit_buffer_size, "Number of entries in the tlb split debug buffer");
static int tlbsplit_emulate_on_violation = 0x0 ;
module_param(tlbsplit_emulate_on_violation, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(tlbsplit_emulate_on_violation, "On page flip 0-just retry 1-emulate instruction");
static long tlbsplit_magic = 0x0 ;
module_param(tlbsplit_magic, long, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(tlbsplit_magic, "Check rdx for this value in tlb split calls. Ignored if zero");
static int tlbsplit_log_read_stacks = 0x0 ;
module_param(tlbsplit_log_read_stacks, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(tlbsplit_log_read_stacks, "Log up to 5 stack pages of read flips into a file");

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))

#define PTE_WRITE (1<<1)
#define PTE_READ (1<<0)
#define PTE_EXECUTE (1<<2)

//#define KVM_MAX_TRACKER 0x200

struct kvm_ept_violation_tracker_entry {
	u32 counter;
	u16 read;
	u16 vmnumber;
	u64 gva;
	u64 rip;
	u64 cr3;
} __attribute__( ( packed ) ) ;

atomic_t split_tracker_next_write;
struct kvm_ept_violation_tracker {
	int max_number_of_entries;
	struct kvm_ept_violation_tracker_entry entries[];
} __attribute__( ( packed ) ) *split_tracker;

static struct dentry *split_dentry;

static size_t debug_buffer_size;

static int next_vm;

/* read file operation */
static ssize_t split_counter_reader(struct file *fp, char __user *user_buffer,
                                size_t count, loff_t *position)
{
     return simple_read_from_buffer(user_buffer, count, position, split_tracker, debug_buffer_size);
}

static const struct file_operations split_debug = {
        .read = split_counter_reader,
};

void split_init_debugfs(void) {
	debug_buffer_size = sizeof(int) + sizeof(struct kvm_ept_violation_tracker_entry) * tlbsplit_buffer_size;
	atomic_set(&split_tracker_next_write,0);

	split_tracker = kzalloc(debug_buffer_size, GFP_KERNEL);

	split_tracker->max_number_of_entries = tlbsplit_buffer_size;
	split_dentry = debugfs_create_file("tlb_split", 0444, kvm_debugfs_dir, NULL, &split_debug);
	printk(KERN_INFO "tlb_split_init:debugfs_create_file returned 0%lx allocated:0%ld for %d entries\n",(unsigned long)split_dentry,debug_buffer_size,tlbsplit_buffer_size);
	next_vm = 0;
}

void _register_ept_flip(gva_t gva,gva_t rip,unsigned long cr3,struct kvm *kvm,bool read) {
	int vmnumber = kvm->splitpages->vmcounter;
	int counter = atomic_inc_return(&split_tracker_next_write);
	int nextRow = (counter - 1) % split_tracker->max_number_of_entries;
	if (gva >= kvm->splitpages->adjust_from && gva <= kvm->splitpages->adjust_to) 
		split_tracker->entries[nextRow].gva = gva - kvm->splitpages->adjust_by;
	else
		split_tracker->entries[nextRow].gva = gva;
	if (rip >= kvm->splitpages->adjust_from && rip <= kvm->splitpages->adjust_to) 
		split_tracker->entries[nextRow].rip = rip - kvm->splitpages->adjust_by;
	else
		split_tracker->entries[nextRow].rip = rip;
	split_tracker->entries[nextRow].cr3 = cr3;
	split_tracker->entries[nextRow].vmnumber = vmnumber;
	split_tracker->entries[nextRow].read = read;
	split_tracker->entries[nextRow].counter = counter;
}

void split_shutdown_debugfs(void) {
	debugfs_remove(split_dentry);
	kfree(split_tracker);
}

bool tlb_split_init(struct kvm *kvm) {
	kvm->splitpages = kzalloc(sizeof(struct kvm_splitpages), GFP_KERNEL);
	if (kvm->splitpages!=NULL) {
		kvm->splitpages->vmcounter = next_vm++;
		return true;
	}
	else
		return false;
}

void kvm_split_tlb_freepage(struct kvm_splitpage *page)
{
	page->cr3 = 0;
	page->gpa = 0;
	page->active = 0;
	page->gva = 0;
	page->codeaddr = 0;
	page->dataaddrphys = 0;
	if (page->dataaddr) {
		kfree(page->dataaddr);
		page->dataaddr = NULL;
	}
	if (page->codepage) {
		kfree(page->codepage);
		page->codepage = NULL;
	}
}
EXPORT_SYMBOL_GPL(kvm_split_tlb_freepage);

void kvm_split_tlb_deactivateall(struct kvm *kvm) {
	struct kvm_splitpages *spages = kvm->splitpages;
	int i;
	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++)
		kvm_split_tlb_freepage(&spages->pages[i]);
	kfree(kvm->splitpages);
}
EXPORT_SYMBOL_GPL(kvm_split_tlb_deactivateall);

static struct kvm_splitpage* _split_tlb_findpage(struct kvm *kvms,gpa_t gpa) {
	int i;
	struct kvm_splitpage* found;
	gpa_t pagestart;
	pagestart = gpa&PAGE_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->gpa == pagestart)
			return found;
	}
	return NULL;
}

struct kvm_splitpage* split_tlb_findpage(struct kvm *kvms,gpa_t gpa) {
	if (gpa&PAGE_MASK)
		return _split_tlb_findpage(kvms,gpa);
	else
		return NULL;
}
EXPORT_SYMBOL_GPL(split_tlb_findpage);

struct kvm_splitpage* split_tlb_findpage_gva_cr3(struct kvm *kvms, gva_t gva, ulong cr3) {
	struct kvm_splitpage* found;
	gva_t pagestart;
	int i;
	pagestart = gva&PAGE_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->gva == pagestart && found->cr3 == cr3)
			return found;
	}
	return NULL;
}


int split_tlb_setdatapage(struct kvm_vcpu *vcpu, gva_t gva, gva_t datagva, ulong cr3) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	gpa_t translated;
	int r;
	access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split_tlb_setdatapage: gva:0x%lx gpa not found %d\n",gva,exception.error_code);
		gpa = 0;
	}
	printk(KERN_INFO "split_tlb_setdatapage: cr3:0x%lx gva:0x%lx gpa:0x%llx\n",cr3,gva,gpa);
	if (gpa!=0)
		page = split_tlb_findpage(vcpu->kvm,gpa);
	else
		page = split_tlb_findpage_gva_cr3(vcpu->kvm,gva,cr3);
	if (page == NULL) {
		page = _split_tlb_findpage(vcpu->kvm,0);
		if (page == NULL) {
			printk(KERN_WARNING "No more slots in the split page table\n");
			return 0;
		}
		page->cr3 = cr3;
		page->gpa = gpa&PAGE_MASK;
		page->gva = gva&PAGE_MASK;
		page->dataaddr = kmalloc(4096,GFP_KERNEL);
		page->dataaddrphys = virt_to_phys(page->dataaddr);
		page->codepage = kmalloc(4096,GFP_KERNEL);
		page->codeaddr = virt_to_phys(page->codepage);
		BUG_ON(((long unsigned int)page->dataaddr&~PAGE_MASK)!=0);
		BUG_ON(((long unsigned int)page->codepage&~PAGE_MASK)!=0);
		translated = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, datagva&PAGE_MASK, access, &exception);
		if (translated == UNMAPPED_GVA) {
			printk(KERN_WARNING "split:tlb_setdatapage gva:0x%lx gpa not found for data %d\n",datagva,exception.error_code);
			return 0;
		}
		r = kvm_read_guest(vcpu->kvm,translated,page->dataaddr,4096);
		memcpy(page->codepage,page->dataaddr,4096);
		printk(KERN_INFO "split:tlb_setdatapage cr3:0x%lx gva:0x%lx gpa:0x%llx data:0x%llx/0x%llx code:0x%llx/0x%llx copy result:%d\n",cr3,gva,gpa,(u64)page->dataaddr,virt_to_phys(page->dataaddr),(u64)page->codepage,virt_to_phys(page->codepage),r);
	} else {
		printk(KERN_WARNING "Already a page for: gpa:0x%llx with cr3:0x%lx and gva=0x%lx\n",gpa,page->cr3,page->gva);
		return 0;
	}
	return 1;
}
//EXPORT_SYMBOL_GPL(split_tlb_setdatapage);

int split_tlb_findspte_callback(u64* sptep, int level, int last, int large) {
	return (last && !large);
}

int split_tlb_findspte_callback_print(u64* sptep, int level, int last, int large) {
	printk(KERN_WARNING "split_tlb_findspte: sptep 0x%llx level:%d large=%d last=%d \n",*sptep,level,large,last);
	return (last && !large);
}


int split_tlb_activatepage(struct kvm_vcpu *vcpu, gva_t gva, ulong cr3) {
	gpa_t gpa;
	u32 access;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	u64* sptep;
	//struct kvm_shadow_walk_iterator iterator;
	gfn_t gfn;

	access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split:split_tlb_activatepage gva:0x%lx gpa not found %d\n",gva,exception.error_code);
		return 0;
	}
	page = split_tlb_findpage_gva_cr3(vcpu->kvm,gva,cr3);
	if (page == NULL) {
		printk(KERN_WARNING "split:tlb_activatepage page not foundcr3:0x%lx gva:0x%lx translated gpa:0x%llx \n",cr3,gva,gpa);
		return 0;
	}
	printk(KERN_INFO "split_tlb_activatepage found page cr3:0x%lx gva:0x%lx gpa:0x%llx page_gpa:0x%llx\n",cr3,gva,gpa,page->gpa);
	if (page->gpa != (gpa&PAGE_MASK) ) {
		printk(KERN_WARNING "split:tlb_activatepage gpa changed 0x%llx->0x%llx, adjusting\n",page->gpa,gpa&PAGE_MASK);
		page->gpa = gpa&PAGE_MASK;
	}

	gfn = gpa >> PAGE_SHIFT;
	sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
	if (sptep!=NULL) {
		u64 newspte = *sptep & ~(VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK);
		page->original_spte = *sptep;
		newspte&=~PT64_BASE_ADDR_MASK;
		newspte|=page->codeaddr&PT64_BASE_ADDR_MASK;
		//newspte = 0L;
		printk(KERN_INFO "split_tlb_activatepage: spte=0x%llx->newspte=0x%llx ,sptep=x%llx\n",*sptep,newspte,(u64)sptep);
        	*sptep = newspte;
        	page->active = true;
		kvm_flush_remote_tlbs(vcpu->kvm);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_activatepage: spte not found 0x%llx\n",gpa);
		sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback_print);
	}
	return 0;
}
//EXPORT_SYMBOL_GPL(split_tlb_activatepage);

int split_tlb_copymem(struct kvm_vcpu *vcpu, gva_t from, gva_t to, u64 count, ulong cr3) {
	printk(KERN_INFO "split_tlb_copymem: from:0x%lx to:%lx count:%lld cr3:%lx\n",from,to,count,cr3);
	if (count>MAX_PATCH_SIZE)
		return 0;
	else {
		int r;
		char buf[count];
		u64 remains = count;
		struct x86_exception exception;
		u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
		gpa_t from_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, from, access, &exception);
		//gpa_t to_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, to, access, &exception);
		if (from_gpa == UNMAPPED_GVA) {
			printk(KERN_WARNING "split_tlb_copymem: from gva:0x%lx gpa not found  %d\n",from,exception.error_code);
			return 0;
		}
/*		if (to_gpa == UNMAPPED_GVA) {
			printk(KERN_WARNING "split_tlb_copymem: to gva:0x%lx gpa not found  %d\n",to,exception.error_code);
			return 0;
		}
*/
		r = kvm_read_guest(vcpu->kvm,from_gpa,buf,count);
		if (r != 0) {
			printk(KERN_WARNING "split_tlb_copymem: read gva:0x%lx gpa:0x%llx failed with the result %d\n",from,from_gpa,r);
			return 0;
		}
		while (remains > 0) {
			gva_t cur_gva = to+(count-remains);
			struct kvm_splitpage* page = split_tlb_findpage_gva_cr3(vcpu->kvm,cur_gva,cr3);
			u64 to_copy;
			u64 page_offset = cur_gva & (PAGE_SIZE - 1);
			char *to_addr;
			char *from_addr = buf+(count-remains);
			if (page == NULL) {
				printk(KERN_WARNING "split_tlb_copymem: split page not found gva:0x%lx remains:%lld count:%lld\n",to,remains,count);
				return 0;
			}
			if ( ( cur_gva & PAGE_MASK ) == ((cur_gva+remains) & PAGE_MASK ) ) {
				to_copy = remains;
				remains = 0;
			} else {
				to_copy = ( cur_gva & PAGE_MASK ) + PAGE_SIZE - cur_gva;
				remains -= to_copy;
			}
			to_addr = ((char*)(page->codepage)) + page_offset;
			printk(KERN_INFO "split_tlb_copymem: copying %lld bytes to gva:0x%lx/hva:0x%llx\n",to_copy,cur_gva,(u64)to_addr);
			memcpy(to_addr,from_addr,to_copy);
		}
/*
		r = kvm_write_guest(vcpu->kvm,to_gpa,buf,count);
		if (r != 0) {
			printk(KERN_WARNING "split_tlb_copymem: write gva:0x%lx gpa:0x%llx failed with the result %d\n",to,to_gpa,r);
			return 0;
		}
*/		
		return 1;
	}
}

int split_tlb_setadjuster(struct kvm_vcpu *vcpu, gva_t from, gva_t to, u64 by) {
	vcpu->kvm->splitpages->adjust_from = from;
	vcpu->kvm->splitpages->adjust_to = to;
	vcpu->kvm->splitpages->adjust_by = by;
	printk(KERN_DEBUG "split_tlb_setadjuster: from:0x%lx to:0x%lx by 0x%llx vm:0x%x\n",from,to,by,vcpu->kvm->splitpages->vmcounter);
	return 1;
}

int split_tlb_restore_spte_atomic(struct kvm *kvms,gfn_t gfn,u64* sptep,hpa_t stepaddr) {
	if (sptep!=NULL) {
		u64 newspte = *sptep;
		if ((newspte&VMX_EPT_READABLE_MASK)==0||(newspte&VMX_EPT_EXECUTABLE_MASK)==0||(newspte&VMX_EPT_WRITABLE_MASK)==0) {
			newspte|=VMX_EPT_READABLE_MASK|VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=stepaddr & PT64_BASE_ADDR_MASK;
			printk(KERN_WARNING "split_tlb_restore_spte_atomic: fixing spte 0%llx->0%llx for 0%llx\n", *sptep, newspte, gfn<<PAGE_SHIFT);
			*sptep = newspte;
		} else
			printk(KERN_WARNING "split_tlb_restore_spte_atomic: spte for 0%llx seems untouched: 0%llx\n", gfn<<PAGE_SHIFT, *sptep);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_restore_spte_atomic: spte not found for 0x%llx\n", gfn<<PAGE_SHIFT);
		return 0;
	}
}

hpa_t ts_gfn_to_pfa(struct kvm_vcpu *vcpu,gfn_t gfn) {
struct kvm_memory_slot *slot;
bool async,writable;
kvm_pfn_t pfn;

	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	async = false;
	pfn = __gfn_to_pfn_memslot(slot, gfn, false, &async, false, &writable);
	if (async || !writable) {
		printk(KERN_WARNING "ts_gfn_to_pfn: unexpected async:%d writable%d\n", async, writable);
		WARN_ON(1);
	}
	return pfn << PAGE_SHIFT;
	
}

int split_tlb_restore_spte(struct kvm_vcpu *vcpu,gfn_t gfn) {
	int result;
	u64* sptep;
	hpa_t stepaddr = ts_gfn_to_pfa(vcpu,gfn) ;
//	if (async || !writable)
//		printk(KERN_WARNING "split_tlb_restore_spte: unexpected async:%d writable%d gpa:0%llx hfn:0%llx\n", async, writable, gfn<<PAGE_SHIFT,stepaddr);
	spin_lock(&vcpu->kvm->mmu_lock);
	sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
	if (sptep!=NULL && *sptep==0) {
		spin_unlock(&vcpu->kvm->mmu_lock);
		printk(KERN_WARNING "split_tlb_restore_spte: zero spte, falling back to default handler gpa:0%llx\n", gfn<<PAGE_SHIFT);
		return 0;
	}
	result = split_tlb_restore_spte_atomic(vcpu->kvm,gfn,sptep,stepaddr);
	spin_unlock(&vcpu->kvm->mmu_lock);
	return result;
}

/*
int split_tlb_flip_to_code(struct kvm *kvms,hpa_t hpa,u64* sptep) {
	if (sptep!=NULL) {
		u64 newspte = *sptep;
		if ((newspte&VMX_EPT_READABLE_MASK)!=0||(newspte&VMX_EPT_EXECUTABLE_MASK)==0||(newspte&VMX_EPT_WRITABLE_MASK)==0) {
			WARN_ON(hpa==0);
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_READABLE_MASK);
			newspte|=VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=hpa&PT64_BASE_ADDR_MASK;
			printk(KERN_WARNING "split_tlb_flip_to_code: fixing spte 0%llx->0%llx for 0%llx\n", *sptep, newspte, hpa);
			*sptep = newspte;
		} else
			printk(KERN_WARNING "split_tlb_flip_to_code: spte for 0%llx seems untouched: 0%llx\n", hpa, *sptep);
		return 1;
	} else {
		printk(KERN_WARNING "split_tlb_flip_to_code: spte not found for hpa 0x%llx\n", hpa);
		return 0;
	}
}
*/


int split_tlb_freepage_by_gpa(struct kvm_vcpu *vcpu, gpa_t gpa) {
	gfn_t gfn;
	struct kvm_splitpage* page;
	page = split_tlb_findpage(vcpu->kvm,gpa);
	if (page!=NULL) {
		if (page->active) {
			//int rc = kvm_write_guest(vcpu->kvm,gpa&PAGE_MASK,page->dataaddr,4096);
			gfn = gpa >> PAGE_SHIFT;
			split_tlb_restore_spte(vcpu,gfn);
			printk(KERN_WARNING "split_tlb_freepage_by_gpa: copying data cr3:0x%lx gva:0x%lx gpa:0x%llx\n",page->cr3,page->gva,page->gpa);
		} else {
			printk(KERN_WARNING "split_tlb_freepage_by_gpa: inactive page cr3:0x%lx gva:0x%lx gpa:0x%llx\n",page->cr3,page->gva,page->gpa);
		}
		kvm_split_tlb_freepage(page);
		return 1;
	} else
		printk(KERN_WARNING "split_tlb_freepage_by_gpa: page not found gpa:0x%llx\n",gpa);
	return 0;
}

int split_tlb_freepage(struct kvm_vcpu *vcpu, gva_t gva) {
	gpa_t gpa;
	u32 access;
	struct x86_exception exception;

	access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, gva, access, &exception);
	if (gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "split:tlb_freepage gva:0x%lx gpa not found %d\n",gva,exception.error_code);
		return 0;
	}
	return split_tlb_freepage_by_gpa(vcpu,gpa);
}

static int read_guest_by_virtual(struct kvm_vcpu *vcpu, gva_t from_gva, void* into, u64 count) {
	int r;
	struct x86_exception exception;
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	u64 remaining = count;
	char* into_c = (char*) into;
	while (remaining>0) {
		gpa_t from_gpa;
		u64 copy_now;
		if ( ( (from_gva + remaining - 1) & PAGE_MASK ) != ( from_gva & PAGE_MASK ) ) {
			copy_now = ( ( from_gva + PAGE_SIZE ) & PAGE_MASK ) - from_gva;
		} else {
			copy_now = remaining;
	    }
		from_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, from_gva, access, &exception);	
		if (from_gpa == UNMAPPED_GVA) {
				printk(KERN_WARNING "read_guest_by_virtual: for gva:0x%lx gpa not found %d\n",from_gva,exception.error_code);
				return 0;
		}
		//printk(KERN_INFO "read_guest_by_virtual: reading %lld bytes from gva:0x%lx to 0x%llx\n", copy_now, from_gva, (u64)into_c);
		r = kvm_read_guest(vcpu->kvm,from_gpa,into_c,copy_now);
		if (r != 0) {
			printk(KERN_WARNING "read_guest_by_virtual: read gva:0x%lx gpa:0x%llx failed with the result %d\n",from_gva,from_gpa,r);
			return 0;
		}
		from_gva += copy_now;
		into_c += copy_now;
		remaining -= copy_now;
	}
	return 1;
}

#define MAX_PATH_LENGTH 4096

int split_tlb_procinfo(struct kvm_vcpu *vcpu,void* buf,uint buf_size,gva_t *user_stack) {
	struct kvm_segment gs;
	TEB guest_teb;
	PEB guest_peb;
	RTL_USER_PROCESS_PARAMETERS guest_upp;
	int guest_cpl = kvm_x86_ops->get_cpl(vcpu);
	gva_t guest_teb_addr;
	char* printbuf = (char*) buf;
	int printed;
	int remains = buf_size;
	
	memset(buf,0,buf_size);
	kvm_get_segment(vcpu, &gs, VCPU_SREG_GS);
	printed = scnprintf(printbuf,remains,"gs:(base=%llx,limit=%x,selector=%x) cpl:%d\n",gs.base,gs.limit,gs.selector,guest_cpl);
	printbuf += printed;
	remains -= printed;
	//printk(KERN_INFO "split_tlb_procinfo: gs:(base=%llx,limit=%x,selector=%x) cpl:%d\n",gs.base,gs.limit,gs.selector,guest_cpl);
	if (guest_cpl == 0) {
		struct msr_data kernel_gs_base;
		kernel_gs_base.index = 0xC0000102;
		kernel_gs_base.host_initiated = false;
		kvm_x86_ops->get_msr(vcpu,&kernel_gs_base);
		printed = scnprintf(printbuf,remains,"got MSR 0xC0000102 as %llx\n",kernel_gs_base.data);
		printbuf += printed;
		remains -= printed;
		//printk(KERN_INFO "split_tlb_procinfo: got MSR 0xC0000102 as %llx", kernel_gs_base.data);
		guest_teb_addr = kernel_gs_base.data;
		//0x1A8
		if (read_guest_by_virtual(vcpu,gs.base+0x10,user_stack,sizeof *user_stack) == 0) {
			printed = scnprintf(printbuf,remains,"Got error reading user stack\n");
			printbuf += printed;
			remains -= printed;
			*user_stack = 0;
		} else {
			printed = scnprintf(printbuf,remains,"User stack:%lx\n",*user_stack);
			printbuf += printed;
			remains -= printed;
		}
	} else if (guest_cpl == 3) {
		guest_teb_addr = gs.base;
		*user_stack = 0;
	} else {
		*user_stack = 0;
		return 0;
	}
	
	if (read_guest_by_virtual(vcpu,guest_teb_addr,&guest_teb,sizeof guest_teb) == 0)
		return 0;
		
	if (read_guest_by_virtual(vcpu,(gva_t)guest_teb.ProcessEnvironmentBlock,&guest_peb,sizeof guest_peb) == 0)
		return 0;

	if (read_guest_by_virtual(vcpu,(gva_t)guest_peb.ProcessParameters,&guest_upp,sizeof guest_upp) == 0)
		return 0;

	printed = scnprintf(printbuf,remains,"peb.ImageBase: %llx ImagePathName.length %d ImagePathName.buffer %llx\n", (u64)guest_peb.ImageBaseAddress, guest_upp.ImagePathName.Length, (u64)guest_upp.ImagePathName.Buffer);
	printbuf += printed;
	remains -= printed;

	//printk(KERN_INFO "split_tlb_procinfo: peb.ImageBase: %llx ImagePathName.length %d ImagePathName.buffer %llx\n", (u64)guest_peb.ImageBaseAddress, guest_upp.ImagePathName.Length, (u64)guest_upp.ImagePathName.Buffer);
	if (guest_upp.ImagePathName.Length < MAX_PATH_LENGTH) {
		WORD* buf = kmalloc(guest_upp.ImagePathName.Length*2, GFP_KERNEL);
		char* buf2 = kmalloc(guest_upp.ImagePathName.Length+1, GFP_KERNEL);
		int i;
		if (read_guest_by_virtual(vcpu,(gva_t)guest_upp.ImagePathName.Buffer,buf,guest_upp.ImagePathName.Length * 2) == 0)
			return 0;
		for (i = 0; i < guest_upp.ImagePathName.Length; i++) {
			buf2[i] = (char)buf[i];
		}
		buf2 [guest_upp.ImagePathName.Length] = 0;
		printed = scnprintf(printbuf,remains,"image path=%s\n", buf2);
		printbuf += printed;
		remains -= printed;
		kfree(buf2);
		kfree(buf);
		//printk(KERN_INFO "split_tlb_procinfo: image path=%s\n",buf2);		
	} else { 
		printed = scnprintf(printbuf,remains,"iimage path too long, ignoring\n");
		printbuf += printed;
		remains -= printed;
		//printk(KERN_INFO "split_tlb_procinfo: image path too long, ignoring");
	}
	return 1;
}

static void print_stack_pages_to_log(struct kvm_vcpu *vcpu,struct file *file,int count, gva_t rsp, loff_t *pos, char * buffer) {
	int access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	int cntr, pages_printed = 0;
	gpa_t gpa;
	struct x86_exception exception;
	
	for (cntr=0; cntr < count; cntr++) {
		gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, (rsp+PAGE_SIZE*cntr)&PT64_BASE_ADDR_MASK, access, &exception);
		if (gpa == UNMAPPED_GVA) {
			break;
			//printk(KERN_WARNING "print_stack_pages_to_log: stack gva:0x%llx gpa not found %d\n",rsp&PT64_BASE_ADDR_MASK,exception.error_code);
		} else {
			pages_printed ++;
			if (kvm_read_guest_page(vcpu->kvm,gpa>>PAGE_SHIFT,buffer,0,0x1000))
				printk(KERN_WARNING "print_stack_pages_to_log: stack reading failed at gpa 0x%llx\n",gpa);
			else {
				if (cntr==0) {
					int bpos;
					for (bpos = 0; bpos < (rsp&0xFFF); bpos++)
						buffer[bpos] = 0xBE;
				}
				vfs_write(file, buffer, PAGE_SIZE, pos);
				//pos += PAGE_SIZE;
				//rsp += PAGE_SIZE;
			}
		}
	}
	printk(KERN_INFO "print_stack_pages_to_log: stack gva:0x%lx printed 0%d pages\n",rsp,pages_printed);
}

static void log_read_flip(struct kvm_vcpu *vcpu,unsigned long rip) {
	int i;
	bool found =false;
	if (tlbsplit_log_read_stacks == 0)
		return;
	for (i=0; i<KVM_SPLIT_PAGES_TRACKER_SIZE; i++) {
		if (vcpu->kvm->splitpages->gvas_logged[i]==rip) {
			found = true;
			break;
		}
	}
	if (found)
		return;
	for (i=0; i<KVM_SPLIT_PAGES_TRACKER_SIZE; i++) {
		if (vcpu->kvm->splitpages->gvas_logged[i]==0) {
			vcpu->kvm->splitpages->gvas_logged[i] = rip;
			found = true;
			break;
		}
	}
	if (found) {
		char * buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
		struct file *file;
		unsigned long rsp = kvm_register_read(vcpu, VCPU_REGS_RSP);

		mm_segment_t old_fs;
		loff_t pos = 0;

		old_fs = get_fs();  //Save the current FS segment PT64_BASE_ADDR_MASK
		set_fs(get_ds());
		if (buffer) {
			snprintf(buffer,PAGE_SIZE,"/var/tmp/vm0x%x_rip0x%lx.dmp",vcpu->kvm->splitpages->vmcounter,rip);
			printk(KERN_INFO "log_read_flip: logging details for rip 0x%lx rsp 0x%lx file:%s\n",rip,rsp,buffer);
			file = filp_open(buffer, O_WRONLY|O_CREAT, 0644);
			if (file && !IS_ERR(file)) {
				int access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
				struct x86_exception exception;
				gpa_t gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, rip&PT64_BASE_ADDR_MASK, access, &exception);
				if (gpa == UNMAPPED_GVA) {
					printk(KERN_WARNING "split log_read_flip: code gva:0x%llx gpa not found %d\n",rip&PT64_BASE_ADDR_MASK,exception.error_code);
				} else {
					int r;
					gva_t user_stack;
					printk(KERN_INFO "split log_read_flip: code gva:0x%llx gpa 0x%llx\n",rip&PT64_BASE_ADDR_MASK,gpa);
					r = kvm_read_guest_page(vcpu->kvm,gpa>>PAGE_SHIFT,buffer,0,0x1000);
					if (r)
						printk(KERN_WARNING "split log_read_flip: code reading failed at gpa 0x%llx\n",gpa);
					else {
						vfs_write(file, buffer, PAGE_SIZE, &pos);
						//pos += 0x1000;
					}
					print_stack_pages_to_log(vcpu,file,5,rsp,&pos,buffer);
					if (split_tlb_procinfo(vcpu,buffer,PAGE_SIZE,&user_stack)) {
						vfs_write(file, buffer, PAGE_SIZE, &pos);
						if (user_stack!=0) {
							print_stack_pages_to_log(vcpu,file,5,user_stack,&pos,buffer);
						}
					}
				}
				filp_close(file,NULL);
			}
			kfree(buffer);
		}
		set_fs(old_fs); //Reset to save FS
	}
}

int split_tlb_flip_page(struct kvm_vcpu *vcpu, gpa_t gpa, struct kvm_splitpage* splitpage, unsigned long exit_qualification)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long cr3 = kvm_read_cr3(vcpu);
	unsigned long now_tick;
	phys_addr_t dataaddrphys = virt_to_phys(splitpage->dataaddr);
	phys_addr_t codeaddrphys = virt_to_phys(splitpage->codepage);
	if (dataaddrphys != splitpage->dataaddrphys) {
		printk(KERN_WARNING "split_tlb_flip_page: Data hpa changed from:0x%llx to:0x%llx\n",splitpage->dataaddrphys,dataaddrphys);
		splitpage->dataaddrphys = dataaddrphys;
	}	
	if (codeaddrphys != splitpage->codeaddr) {
		printk(KERN_WARNING "split_tlb_flip_page: Code hpa changed from:0x%llx to:0x%llx\n",splitpage->codeaddr,codeaddrphys);
		splitpage->codeaddr = codeaddrphys;
	}	

	if (exit_qualification & PTE_WRITE) //write
	{
		//int rc;
		printk(KERN_WARNING "split_tlb_flip_page: WRITE EPT fault at 0x%llx. detourpa:0x%llx rip:0x%lx\n vcpuid:%d Removing the page\n",gpa,dataaddrphys,rip,vcpu->vcpu_id);
		if (split_tlb_restore_spte(vcpu,gfn)==0)
			return 0;
		//rc = kvm_write_guest(vcpu->kvm,gpa&PAGE_MASK,splitpage->dataaddr,4096);
		kvm_split_tlb_freepage(splitpage);
		printk(KERN_WARNING "split_tlb_flip_page: WRITE EPT fault at 0x%llx, page removed\n",gpa);
	} else if (exit_qualification & PTE_READ) //read
	{
		u64* sptep;
		//hpa_t stepaddr = ts_gfn_to_pfa(vcpu,gfn);
		log_read_flip(vcpu,rip);
		spin_lock(&vcpu->kvm->mmu_lock);
		sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
		if (exit_qualification & PTE_EXECUTE) //TODO handle execute&read, not sure if needed
			{
				printk(KERN_ERR "split_tlb_flip_page: read&execute EPT fault at 0x%llx. Need to handle it properly \n",gpa);
			}
		if (sptep!=NULL) {
			u64 newspte = *sptep;
			if (newspte==0) {
				printk(KERN_WARNING "split_tlb_flip_page: found zero spte(READ):0x%llx/0x%llx restoring to 0x%llx\n",gpa,(u64)sptep,splitpage->original_spte);
				newspte = splitpage->original_spte;
			}
			if ((newspte&(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK|VMX_EPT_READABLE_MASK))==0) {
				printk(KERN_WARNING "split_tlb_flip_page: sptep last 3 bits are 0 for gpa:0x%llx \n",gpa);
			}
			//splitpage->codeaddr = stepaddr;
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK);
			newspte|=VMX_EPT_READABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=dataaddrphys&PT64_BASE_ADDR_MASK;
			//printk(KERN_WARNING "split_tlb_flip_page: read EPT fault at 0x%llx/0x%llx -> 0x%llx detourpa:0x%llx rip:0x%lx\n vcpuid:%d\n",gpa,*sptep,newspte,detouraddr,rip,vcpu->vcpu_id);
			*sptep = newspte;
		} else {
			printk(KERN_ERR "split_tlb_flip_page: sptep not found for 0x%llx \n",gpa);
			split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback_print);
		}
		spin_unlock(&vcpu->kvm->mmu_lock);
		_register_ept_flip(splitpage->gva,rip,cr3,vcpu->kvm,true);
		now_tick = jiffies;
		if ((rip == vcpu->split_pervcpu.last_read_rip) && (now_tick - vcpu->split_pervcpu.flip_tick) < HZ ) {
			vcpu->split_pervcpu.last_read_count++;
			vcpu->split_pervcpu.flip_tick = now_tick;
		} else {
			vcpu->split_pervcpu.last_read_rip = rip;
			vcpu->split_pervcpu.last_read_count = 0;
			vcpu->split_pervcpu.flip_tick = now_tick;
		}
	} else if (exit_qualification & PTE_EXECUTE) //execute
	{
		u64* sptep;
		//hpa_t stepaddr = ts_gfn_to_pfa(vcpu,gfn);
//		if (async || !writable)
//			printk(KERN_WARNING "split_tlb_flip_page: unexpected async:%d writable%d\n", async, writable);
		spin_lock(&vcpu->kvm->mmu_lock);
		sptep = split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback);
		if (sptep!=NULL) {
			u64 newspte = *sptep;
			if (newspte==0) {
				printk(KERN_WARNING "split_tlb_flip_page: found zero spte (EXEC):0x%llx/0x%llx  restoring to 0x%llx\n",gpa,(u64)sptep,splitpage->original_spte);
				newspte = splitpage->original_spte;
			}
			if ((newspte&(VMX_EPT_WRITABLE_MASK|VMX_EPT_EXECUTABLE_MASK|VMX_EPT_READABLE_MASK))==0) {
				printk(KERN_WARNING "split_tlb_flip_page: sptep last 3 bits are 0 for gpa:0x%llx \n",gpa);
			}
			newspte&=~(VMX_EPT_WRITABLE_MASK|VMX_EPT_READABLE_MASK);
			newspte|=VMX_EPT_EXECUTABLE_MASK;
			newspte&=~PT64_BASE_ADDR_MASK;
			newspte|=codeaddrphys&PT64_BASE_ADDR_MASK;
			//printk(KERN_WARNING "split_tlb_flip_page: execute EPT fault at 0x%llx/0x%llx -> 0x%llx detourpa:0x%llx rip:0x%lx\n vcpuid:%d\n",gpa,*sptep,newspte,detouraddr,rip,vcpu->vcpu_id);
			*sptep = newspte;
		} else {
			printk(KERN_ERR "split_tlb_flip_page: sptep not found for 0x%llx \n",gpa);
			split_tlb_findspte(vcpu,gfn,split_tlb_findspte_callback_print);
		}
		spin_unlock(&vcpu->kvm->mmu_lock);
		_register_ept_flip(splitpage->gva,rip,cr3,vcpu->kvm,false);
		now_tick = jiffies;
		if ( rip == vcpu->split_pervcpu.last_exec_rip && (now_tick - vcpu->split_pervcpu.flip_tick) < HZ) {
			vcpu->split_pervcpu.last_exec_count++;
			vcpu->split_pervcpu.flip_tick = now_tick;
		} else {
			vcpu->split_pervcpu.last_exec_rip = rip;
			vcpu->split_pervcpu.last_exec_count = 0;
			vcpu->split_pervcpu.flip_tick = now_tick;
		}
	} else
		printk(KERN_ERR "split_tlb_flip_page: unexpected EPT fault at 0x%llx \n",gpa);
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_flip_page);

int deactivateAllPages(struct kvm_vcpu *vcpu) {
	struct kvm_splitpages *spages = vcpu->kvm->splitpages;
	int i;
	for (i = 0; i < KVM_MAX_SPLIT_PAGES; i++) {
		gva_t gva = spages->pages[i].gva;
		gpa_t gpa = spages->pages[i].gpa;
		if (gva) {
			if (split_tlb_freepage_by_gpa(vcpu,gpa)==0) {
				printk(KERN_WARNING "deactivateAllPages: split_tlb_freepage failed for gva=%lx/gpa=%llx attempting to fix and free it based on saved gpa\n",gva,gpa);
				split_tlb_restore_spte(vcpu,gpa >> PAGE_SHIFT);

				kvm_split_tlb_freepage(spages->pages+i);
			}
		}
	}
	split_tlb_setadjuster(vcpu,0,0,0);
	return 1;
}

int isPageSplit(struct kvm_vcpu *vcpu, gva_t addr ) {
	u32 access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	struct kvm_splitpage* page;
	struct x86_exception exception;
	gpa_t addr_gpa = vcpu->arch.walk_mmu->gva_to_gpa(vcpu, addr, access, &exception);
	if (addr_gpa == UNMAPPED_GVA) {
		printk(KERN_WARNING "isPageSplit: address unmapped gva=%lx\n",addr);
		return 0;
	}
//	printk(KERN_WARNING "isPageSplit: address translated gva=%lx to gpa=0x%llx\n",addr,addr_gpa);
	page = split_tlb_findpage(vcpu->kvm,addr_gpa);
	if (page != NULL)
		return 1;
	else {
		printk(KERN_WARNING "isPageSplit: no split page for gva=%lx to gpa=0x%llx\n",addr,addr_gpa);
		return 0;
	}
}


/*
 * rcx - opcode, rax will have magic word
 *
 * 0x0000: check if support is present
 *
 * 0x0001: Create split context
 * 		rbx - guest virtual address for page
 *
 * 0x0002: Activate page.
 * 		rbx - guest virtual address for page
 *
 * 0x0003: Deactivate page.
 * 		rbx - guest virtual address for page
 *
 * 0x0004: Deactivate all
 * 		return rcx = 1 - success
 * 		rcx = 0 - failure
 *
 * 0x0005: is page present
 * 		rbx - guest virtual address for data
 * 		return rcx = 1 - present
 * 		rcx = 0 - not present
 *
 * 0x0006: Write code for page. Only usable after page is active
 * 		rbx - guest virtual address for data
 * 		rsi - guest virtual address for destination
 * 		r8 - number of bytes
 *
 *
 *
 */

int split_tlb_vmcall_dispatch(struct kvm_vcpu *vcpu)
{
	unsigned long rip,cr3,rcx,rdx,rbx,rsi,r8;
	int result = 0;

	rip = kvm_rip_read(vcpu);
	cr3 = kvm_read_cr3(vcpu);
	rbx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	rdx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	rsi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	r8 = kvm_register_read(vcpu, VCPU_REGS_R8);
	//printk(KERN_DEBUG "VMCALL: rip:0x%lx cr3:0x%lx rcx:0x%lx rdx:0x%lx rsi:0x%lx r8:0x%lx\n",rip,cr3,rcx,rdx,rsi,r8);
	if (tlbsplit_magic != 0 && tlbsplit_magic != rdx) {
		return 0;
	}

	switch (rcx) {
		case 0x0000:
			result = 1;
			break;
		case 0x0001:
			result = split_tlb_setdatapage(vcpu,rbx,rbx,cr3);
			break;
		case 0x0002:
			result = split_tlb_activatepage(vcpu,rbx,cr3);
		        break;
		case 0x0003:
			result = split_tlb_freepage(vcpu,rbx);
			break;
		case 0x0004:
			result = deactivateAllPages(vcpu);
			break;
		case 0x0005:
			result = isPageSplit(vcpu,rbx);
			break;
		case 0x0006:
			result = split_tlb_copymem(vcpu,rbx,rsi,r8,cr3);
			break;
		case 0x1000:
			result = split_tlb_setadjuster(vcpu,rbx,rsi,r8);
			break;
		case 0x1001: {
				char buf[512];
				gva_t user_stack;
				result = split_tlb_procinfo(vcpu,buf,sizeof buf,&user_stack);
				printk(KERN_INFO "VMCALL: split_tlb_procinfo returned %s",buf);
			}
			break;
		default:
			result = 0;
			printk(KERN_WARNING "VMCALL: invalid operation 0x%lx \n",rcx);
	}
	kvm_register_write(vcpu, VCPU_REGS_RCX, result);
	return 1;
}
EXPORT_SYMBOL_GPL(split_tlb_vmcall_dispatch);

int split_tlb_has_split_page(struct kvm *kvms, u64* sptep) {
	struct kvm_splitpage* found;
	int i;
	phys_addr_t pagehpa = *sptep & PT64_BASE_ADDR_MASK;
	for (i=0; i<KVM_MAX_SPLIT_PAGES; i++) {
		found = kvms->splitpages->pages+i;
		if (found->active) {
			//phys_addr_t detouraddr = virt_to_phys(found->dataaddr);
			printk(KERN_WARNING "split_tlb_has_split_page: comparing pagehpa:0x%llx with code/data hpa:0x%llx/0x%llx\n",pagehpa,found->codeaddr,found->dataaddrphys);
			if (pagehpa == found->codeaddr || pagehpa == found->dataaddrphys) {
				printk(KERN_WARNING "split_tlb_has_split_page: found page gva:0x%lx VM:%x reverting to original spte\n",found->gva,kvms->splitpages->vmcounter);
				*sptep = found->original_spte;
				//split_tlb_flip_to_code(kvms,found->codeaddr,sptep);
				return 1;
			}
		}
	}
	printk(KERN_WARNING "split_tlb_has_split_page: did not find split page spte:0x%llx\n",*sptep);
	return 0;
}

int split_tlb_handle_ept_violation(struct kvm_vcpu *vcpu,gpa_t gpa,unsigned long exit_qualification,int* splitresult) {
static int emulate_mode = 0xFFFF;
	struct kvm_splitpage* splitpage;

	splitpage = split_tlb_findpage(vcpu->kvm,gpa);
	if (splitpage!=NULL) {
		//printk(KERN_DEBUG "handle_ept_violation on split page: 0x%llx exitqualification:%lx\n",gpa,exit_qualification);
		if (split_tlb_flip_page(vcpu,gpa,splitpage,exit_qualification)){
			bool emulate_now = 0;
			bool exit_on_same_addr = vcpu->split_pervcpu.last_read_rip == vcpu->split_pervcpu.last_exec_rip;
			int thrashed; 
			if (exit_on_same_addr) 
			   thrashed =  vcpu->split_pervcpu.last_read_count + vcpu->split_pervcpu.last_exec_count;
			else {
				if ( vcpu->split_pervcpu.last_read_count > vcpu->split_pervcpu.last_exec_count )
					thrashed = vcpu->split_pervcpu.last_read_count;
				else
					thrashed = vcpu->split_pervcpu.last_exec_count;
			}
			if ( thrashed >= 4) {
				//int thrashed = vcpu->split_pervcpu.last_read_count + vcpu->split_pervcpu.last_exec_count;
				if (thrashed == 4) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: thrashing detected at 0x%lx qualification: 0x%lx",vcpu->split_pervcpu.last_read_rip,exit_qualification);
					kvm_flush_remote_tlbs(vcpu->kvm);
				}
				if (thrashed >= 8) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: still thrashing at 0x%lx qualification: 0x%lx count: 0x%d, attempting to emulate",vcpu->split_pervcpu.last_read_rip,exit_qualification,thrashed);
					emulate_now = 1;
				}
			}
			if (tlbsplit_emulate_on_violation || emulate_now) {
				int emulation_type = EMULTYPE_RETRY;
				enum emulation_result er;
				if (emulate_mode!=0xFFFF && emulate_mode!=tlbsplit_emulate_on_violation) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: emulation mode changed to true");
				}
				emulate_mode = tlbsplit_emulate_on_violation;
				er = x86_emulate_instruction(vcpu, gpa, emulation_type,  NULL, 0);
				if (er==EMULATE_DONE) {
					*splitresult = 1;
				} else {
					printk(KERN_WARNING "handle_ept_violation on split page after emulation %s\n",er==EMULATE_FAIL?"EMULATE_FAIL":"EMULATE_USER_EXIT or smth");
					*splitresult = 0;

				}
			} else {
				*splitresult = 0;
				if (emulate_mode!=0xFFFF && emulate_mode!=tlbsplit_emulate_on_violation) {
					printk(KERN_INFO "split_tlb_handle_ept_violation: emulation mode changed to false");
				}
				emulate_mode = tlbsplit_emulate_on_violation;
			}

		} else {
			printk(KERN_WARNING "handle_ept_violation split_tlb_flip_page returned 0 page: 0x%llx",gpa);
			return 0;
		}
		return 1;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(split_tlb_handle_ept_violation);
