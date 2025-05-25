use core::{cell::RefCell, ptr::NonNull};

use acpi::AcpiHandler;
use algorithms::{
    idalloc::IdAlloc64Trait,
    unialloc::{UniAllocTrait, UntypedInfo},
};
use ipc::untyped::UntypedCap;
use sel4::{
    init_thread::slot::{CNODE, VSPACE},
    with_ipc_buffer_mut, CapRights, FrameObjectType, ObjectBlueprint, ObjectBlueprintX86,
    VmAttributes,
};

use crate::alloc_control::AllocState;
use ipc::host_paging::{HostPagingContext, SMALL_PAGE_SIZE_BITS};

const DEBUG: bool = false;

struct UsedPage {
    ut: UntypedInfo<UntypedCap>,
    mapped: sel4::cap::_4k,
    vaddr: NonNull<[u8; 1 << SMALL_PAGE_SIZE_BITS]>,
}

pub struct RestrictedAcpiHandler<'a, 'b> {
    alloc_state: &'a AllocState,
    host_paging: &'a HostPagingContext<'b>,

    used_pages: RefCell<heapless::Vec<UsedPage, 4>>,

    // (aligned_start, aligned_end, vaddr)
    mapped: RefCell<heapless::Vec<(usize, usize, u64), 4>>,
}

impl<'a, 'b> RestrictedAcpiHandler<'a, 'b> {
    pub fn new(alloc_state: &'a AllocState, host_paging: &'a HostPagingContext<'b>) -> Self {
        Self {
            alloc_state,
            host_paging,
            used_pages: RefCell::new(heapless::Vec::new()),
            mapped: RefCell::new(heapless::Vec::new()),
        }
    }
}

impl<'a, 'b> Drop for RestrictedAcpiHandler<'a, 'b> {
    fn drop(&mut self) {
        for used in self.used_pages.borrow().iter() {
            CNODE
                .cap()
                .absolute_cptr(used.ut.cap.0.cptr())
                .revoke()
                .expect("Failed to revoke untyped");
            self.alloc_state.borrow_mut().free_device(&used.ut);
            assert!(self
                .alloc_state
                .borrow_mut()
                .capalloc
                .free(used.mapped.bits()));
            assert!(self.host_paging.free_unmapped_page(used.vaddr));
        }
    }
}

impl<'a, 'b, 'c> AcpiHandler for &'c RestrictedAcpiHandler<'a, 'b> {
    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> acpi::PhysicalMapping<Self, T> {
        let page_size = FrameObjectType::GRANULE.bytes();
        let aligned_start = physical_address & !(page_size - 1);
        let aligned_end = (physical_address + size + page_size - 1) & !(page_size - 1);
        assert!(aligned_end - aligned_start == page_size);
        let size_bits = (aligned_end - aligned_start).trailing_zeros() as u8;

        let gen_output = |vaddr: u64| {
            if DEBUG {
                println!(
                    "Mapped ACPI region {:#x}..{:#x} to vaddr {:#x} (requested {:#x}, size {})",
                    aligned_start, aligned_end, vaddr, physical_address, size
                );
            }
            acpi::PhysicalMapping::new(
                physical_address,
                NonNull::new((vaddr + (physical_address - aligned_start) as u64) as *mut T)
                    .unwrap(),
                size,
                aligned_end - aligned_start,
                *self,
            )
        };

        if let Some(x) = self
            .mapped
            .borrow()
            .iter()
            .find(|(start, end, _)| *start == aligned_start && *end == aligned_end)
        {
            return gen_output(x.2);
        }

        let vaddr = with_ipc_buffer_mut(|ipc| self.host_paging.alloc_unmapped_page(ipc));
        let free_page = sel4::cap::_4k::from_cptr(self.alloc_state.alloc_empty_cap());
        let Some(ut) = self
            .alloc_state
            .alloc_device(aligned_start as _, size_bits as _)
        else {
            panic!(
                "Failed to allocate untyped for ACPI mapping at {:#x} size {:#x}",
                physical_address, size
            );
        };
        ut.cap
            .0
            .untyped_retype(
                &ObjectBlueprint::Arch(ObjectBlueprintX86::_4k),
                &CNODE.cap().absolute_cptr(CNODE.cptr()),
                free_page.bits() as _,
                1,
            )
            .expect("Failed to retype untyped to page");
        free_page
            .frame_map(
                VSPACE.cap(),
                vaddr.addr().get(),
                CapRights::read_write(),
                VmAttributes::default(),
            )
            .expect("Failed to map acpi page to vspace");
        self.used_pages
            .borrow_mut()
            .push(UsedPage {
                ut,
                mapped: free_page,
                vaddr,
            })
            .ok()
            .expect("Failed to push untyped");
        self.mapped
            .borrow_mut()
            .push((aligned_start, aligned_end, vaddr.addr().get() as u64))
            .expect("Failed to push mapped region");
        gen_output(vaddr.addr().get() as u64)
    }

    fn unmap_physical_region<T>(_region: &acpi::PhysicalMapping<Self, T>) {}
}
