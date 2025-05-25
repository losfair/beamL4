use algorithms::{
    pagetable::PagingService,
    vm::{
        vcpu::{VcpuException, VcpuStateMask},
        vcpu_decode::{decode_io_port_access, IoDirection},
    },
};
use ipc::{
    msgbuf::{encode_msg, DirectTransfer},
    println,
    vmmsvc::VmmToInitMsg,
};
use sel4::FrameObjectType;
use vmm::{
    fault::DEFAULT_PRIORITY,
    paging::VmPagingContext,
    runtime::{wait_for_fault, EventLoop},
};

use crate::{hypercall, shared::HYPERVISOR_CHANNEL_CAP};

pub async fn emulate_reboot(evl: &EventLoop) {
    wait_for_fault(DEFAULT_PRIORITY, 30, &|state, fault| {
        let io = decode_io_port_access(fault);
        matches!(io.direction, IoDirection::Out)
            && (io.port_number == 0x501 || (io.port_number == 0x64 && (state.eax & 0xff) == 0xfe))
    })
    .await;
    let mut vcpu = evl.vcpu().borrow_mut();
    let vcpu = &mut **vcpu;
    let io = decode_io_port_access(vcpu.fault());
    println!(
        "Reboot requested with io port {:#x}, code {:#x}",
        io.port_number,
        vcpu.state().eax & 0xff
    );
    evl.with_ipcbuf(|ipc| {
        let (msg, _m) = encode_msg(
            ipc,
            &VmmToInitMsg::Reboot { index: u32::MAX },
            DirectTransfer,
            &[],
        );
        ipc.inner_mut()
            .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
    });
    unreachable!()
}

pub async fn emulate_misc_vmcall(evl: &EventLoop) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY + 1, 18, &|_, _| true).await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let eax = vcpu.state().eax as u32;

        // These are intentionally available to unprivileged guest code
        match eax {
            1 => {
                vcpu.state_mut().eax = 0;
                vcpu.state_mut().eip += vcpu.fault().instruction_len;
                evl.with_ipcbuf(|ipc| {
                    vcpu.commit_state(ipc, VcpuStateMask::EAX | VcpuStateMask::EIP)
                });
            }
            _ => {
                evl.with_ipcbuf(|ipc| {
                    vcpu.inject_exception(ipc, VcpuException::GeneralProtectionFault(0))
                });
            }
        }
    }
}

pub async fn emulate_balloon_vmcall(evl: &EventLoop, paging: &'static VmPagingContext<'static>) {
    loop {
        wait_for_fault(DEFAULT_PRIORITY, 18, &|state, _| {
            state.eax as u32 == hypercall::HYPERCALL_GPA_LARGE_UNMAP
        })
        .await;
        evl.ack_fault();
        let mut vcpu = evl.vcpu().borrow_mut();
        let vcpu = &mut **vcpu;
        let eax = vcpu.state().eax as u32;
        let mut success = false;

        if vcpu.state().cs_access_rights_dpl() != 0 {
            evl.with_ipcbuf(|ipc| {
                vcpu.inject_exception(ipc, VcpuException::GeneralProtectionFault(0))
            });
            continue;
        }

        match eax {
            hypercall::HYPERCALL_GPA_LARGE_UNMAP => {
                let gpa = vcpu.state().ebx as usize;
                evl.with_ipcbuf(|ipc| {
                    if gpa & (FrameObjectType::LargePage.bytes() - 1) != 0 {
                        return;
                    }

                    let Some(paddr) = paging
                        .ps
                        .borrow()
                        .ps_guest_phys_to_page_cap(gpa as u64)
                        .and_then(|(_, cap, _)| {
                            let ret = ipc.inner_mut().seL4_X86_Page_GetAddress(cap);
                            if ret.error != 0 {
                                None
                            } else {
                                Some(ret.paddr)
                            }
                        })
                    else {
                        return;
                    };
                    assert_eq!(paddr as usize & (FrameObjectType::LargePage.bytes() - 1), 0);

                    let (msg, _m) = encode_msg(
                        ipc,
                        &VmmToInitMsg::GpaLargeUnmap { paddr },
                        DirectTransfer,
                        &[],
                    );
                    let msg = ipc
                        .inner_mut()
                        .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
                    if msg.get_label() != 1 {
                        println!("W: gpa unmap failed for {:#x}: {}", gpa, msg.get_label());
                        return;
                    }
                    success = true;
                });
            }
            _ => {
                unreachable!()
            }
        }
        evl.with_ipcbuf(|ipc| {
            if success {
                vcpu.state_mut().eip += vcpu.fault().instruction_len;
                vcpu.commit_state(ipc, VcpuStateMask::EIP);
            } else {
                evl.vcpu()
                    .borrow_mut()
                    .inject_exception(ipc, VcpuException::GeneralProtectionFault(0));
            }
        });
    }
}
