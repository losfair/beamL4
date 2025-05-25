use acpi::sdt::madt::{Madt, MadtEntry};
use handler::RestrictedAcpiHandler;
use ipc::host_paging::HostPagingContext;
use sel4::sys::seL4_BootInfoID;

use crate::{alloc_control::AllocState, util::bootinfo::find_bootinfo_entry};

pub mod handler;

#[derive(Debug)]
pub struct AcpiInfo {
    pub ioapic_irq_to_gsi: heapless::FnvIndexMap<u8, u32, 16>,
}

pub fn init(
    bi: &sel4::BootInfoPtr,
    alloc_state: &AllocState,
    host_paging: &HostPagingContext<'_>,
) -> AcpiInfo {
    let data = find_bootinfo_entry(bi, seL4_BootInfoID::SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP)
        .expect("Failed to find ACPI RSDP in bootinfo");
    let acpi_rsdt = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let acpi_rsdt_revision = data[15];

    println!(
        "Loading ACPI RSDT at {:#x}, revision {}",
        acpi_rsdt, acpi_rsdt_revision
    );
    let h = RestrictedAcpiHandler::new(alloc_state, host_paging);
    let tables = unsafe { acpi::AcpiTables::from_rsdt(&h, acpi_rsdt_revision, acpi_rsdt as usize) }
        .expect("Failed to parse ACPI tables");
    // for hdr in tables.table_headers() {
    //     println!("ACPI Table: {:?}", hdr);
    // }

    let madt = tables.find_table::<Madt>().expect("Failed to find MADT");
    // println!("madt: {:?}", madt.get().as_ref());

    let mut ioapic_irq_to_gsi = heapless::FnvIndexMap::new();
    for entry in madt.get().entries() {
        // println!("MADT entry: {:?}", entry);

        if let MadtEntry::InterruptSourceOverride(entry) = &entry {
            ioapic_irq_to_gsi
                .insert(entry.irq, entry.global_system_interrupt)
                .expect("Failed to insert IRQ to GSI mapping");
        }
    }

    AcpiInfo { ioapic_irq_to_gsi }
}
