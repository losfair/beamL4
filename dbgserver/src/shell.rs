use alloc::vec::Vec;
use ipc::{
    msgbuf::{encode_msg, DirectTransfer},
    print, println,
    timer::{SvcTimer, Timer},
    vmmsvc::{VmPagingMode, VmmToInitMsg},
};
use sel4::IpcBuffer;

use crate::HYPERVISOR_CHANNEL_CAP;

pub struct Shell {
    timer: &'static SvcTimer,
    buf: Vec<u8>,
}

impl Shell {
    pub fn new(timer: &'static SvcTimer) -> Self {
        Shell {
            timer,
            buf: Vec::new(),
        }
    }

    pub fn input(&mut self, ipc: &mut IpcBuffer, ch: u8) {
        if ch == b'\n' {
            println!();
            self.handle_cmd(ipc);
            self.buf.clear();
            print!("dbg> ");
        } else {
            if self.buf.len() < 1024 {
                let ch_ = ch as char;
                if ch_.is_ascii() && !ch_.is_control() {
                    print!("{}", ch as char);
                    self.buf.push(ch);
                }
            }
        }
    }

    fn handle_cmd(&mut self, ipc: &mut IpcBuffer) {
        let mut full_cmd = core::str::from_utf8(&self.buf)
            .unwrap_or_default()
            .split(' ');
        let cmd = full_cmd.next().unwrap_or_default();

        match cmd {
            "" => {}
            "time" => {
                println!("{:.06}", self.timer.time_since_boot().as_secs_f64());
            }
            "reboot" => {
                let Ok(index) = full_cmd.next().unwrap_or_default().parse::<u32>() else {
                    println!("invalid index");
                    return;
                };
                let (msg, _) =
                    encode_msg(ipc, &VmmToInitMsg::Reboot { index }, DirectTransfer, &[]);
                let ret = ipc
                    .inner_mut()
                    .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
                if ret.get_label() != 1 {
                    println!("reboot failed");
                } else {
                    println!("ok");
                }
            }
            "kill" => {
                let Ok(index) = full_cmd.next().unwrap_or_default().parse::<u32>() else {
                    println!("invalid index");
                    return;
                };
                let (msg, _) = encode_msg(ipc, &VmmToInitMsg::Kill { index }, DirectTransfer, &[]);
                let ret = ipc
                    .inner_mut()
                    .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
                if ret.get_label() != 1 {
                    println!("kill failed");
                } else {
                    println!("ok");
                }
            }
            "ipcbench" => {
                let (msg, _) = encode_msg(ipc, &VmmToInitMsg::IpcBench, DirectTransfer, &[]);
                let ret = ipc
                    .inner_mut()
                    .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
                if ret.get_label() != 1 || ret.get_length() != 1 {
                    println!("ipcbench failed");
                } else {
                    let latency = ipc.msg_regs()[0];
                    println!("latency: {} ns", latency);
                }
            }
            "mode" => {
                let Ok(index) = full_cmd.next().unwrap_or_default().parse::<u32>() else {
                    println!("invalid index");
                    return;
                };
                let mode = full_cmd.next().unwrap_or_default();
                let mode = match mode {
                    "pv" => VmPagingMode::Pv,
                    "ept_large_page" => VmPagingMode::EptLargePage,
                    "ept_small_page" => VmPagingMode::EptSmallPage,
                    _ => {
                        println!("unknown mode");
                        return;
                    }
                };
                let (msg, _) = encode_msg(
                    ipc,
                    &VmmToInitMsg::SetMode { index, mode },
                    DirectTransfer,
                    &[],
                );
                let ret = ipc
                    .inner_mut()
                    .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
                if ret.get_label() != 1 {
                    println!("mode setting failed");
                } else {
                    println!("ok");
                }
            }
            "affinity" => {
                let Ok(index) = full_cmd.next().unwrap_or_default().parse::<u32>() else {
                    println!("invalid index");
                    return;
                };
                let Ok(affinity) = full_cmd.next().unwrap_or_default().parse::<u32>() else {
                    println!("invalid affinity");
                    return;
                };
                let (msg, _) = encode_msg(
                    ipc,
                    &VmmToInitMsg::SetAffinity { index, affinity },
                    DirectTransfer,
                    &[],
                );
                let ret = ipc
                    .inner_mut()
                    .seL4_Call(HYPERVISOR_CHANNEL_CAP.bits(), msg.into_inner());
                if ret.get_label() != 1 {
                    println!("affinity setting failed");
                } else {
                    println!("ok");
                }
            }
            _ => {
                println!("unknown command");
            }
        }
    }
}
