use sel4::{sys::seL4_Word, FrameObjectType};

pub fn find_bootinfo_entry(bi: &sel4::BootInfoPtr, requested_id: seL4_Word) -> Option<&[u8]> {
    let mut bi_extra = unsafe {
        core::slice::from_raw_parts(
            bi.ptr().cast::<u8>().add(FrameObjectType::GRANULE.bytes()),
            bi.inner().extraLen as usize,
        )
    };

    // seems that sometimes the kernel gives us truncated bootinfo extra
    while bi_extra.len() >= 16 {
        let id = seL4_Word::from_le_bytes(bi_extra[..8].try_into().unwrap());
        let len_including_header = seL4_Word::from_le_bytes(bi_extra[8..16].try_into().unwrap());
        let Some(data) = bi_extra.get(16..len_including_header as usize) else {
            break;
        };
        bi_extra = &bi_extra[len_including_header as usize..];

        if id == requested_id {
            return Some(data);
        }
    }

    None
}
