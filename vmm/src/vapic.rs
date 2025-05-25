use core::cell::RefCell;

use algorithms::vm::vcpu::VcpuStateMask;
use alloc::boxed::Box;
use crate::{
    fault::{MmioRequest, MmioSize, DEFAULT_PRIORITY},
    runtime::{wait_for_fault, EventLoop},
};

pub struct VirtualIoapic {
    // gsi -> irq
    pub redirection_table: RefCell<[u8; 256]>,
}

impl VirtualIoapic {
    pub fn new_boxed() -> Box<Self> {
        unsafe { Box::new_zeroed().assume_init() }
    }

    pub async fn emulate(&self, evl: &EventLoop) {
        let mut ioregsel = 0u32;
        loop {
            wait_for_fault(DEFAULT_PRIORITY, 18, &|state, _| {
                (state.eax == 0x1002 || state.eax == 0x1012)
                    && [0xfec00000, 0xfec00010].contains(&state.ebx)
            })
            .await;
            evl.ack_fault();
            let mut vcpu = evl.vcpu().borrow_mut();
            let vcpu = &mut **vcpu;
            let req = MmioRequest::decode_hypercall(vcpu.state());

            let mut read_value = 0u32;
            match (req.addr, req.write, req.size) {
                (0xfec00000, Some(x), MmioSize::Dword) => {
                    ioregsel = x as u32;
                }
                (0xfec00000, None, MmioSize::Dword) => {
                    read_value = ioregsel;
                }
                (0xfec00010, Some(x), MmioSize::Dword) => {
                    // IOAPIC_REG_REDIR
                    if ioregsel >= 0x10 && ioregsel & 1 == 0 {
                        let gsi = (ioregsel - 0x10) / 2;
                        if gsi <= 0xff {
                            self.redirection_table.borrow_mut()[gsi as usize] = x as u8;
                            println!(
                                "interrupt redirected: gsi {} -> irq {}",
                                gsi,
                                self.redirection_table.borrow()[gsi as usize]
                            );
                        }
                    } else {
                        // println!("ioapic write: {:x} -> {:x}", ioregsel, x);
                    }
                }
                (0xfec00010, None, MmioSize::Dword) => {
                    println!("ioapic read: {:x}", ioregsel);
                }
                _ => {
                    unreachable!()
                }
            }

            let mut mask = VcpuStateMask::EIP;
            if req.write.is_none() {
                vcpu.state_mut().eax = read_value as u64;
                mask |= VcpuStateMask::EAX;
            }
            vcpu.state_mut().eip += vcpu.fault().instruction_len;
            evl.with_ipcbuf(|ipc| vcpu.commit_state(ipc, mask));
        }
    }
}
