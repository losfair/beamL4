use core::time::Duration;

use sel4::{
    cap::{Endpoint, Notification},
    IpcBuffer,
};

use crate::{
    misc::now_cycles,
    msgbuf::{encode_msg, DirectTransfer},
    timesvc::TimeserverMsg,
};

pub trait Timer {
    fn set_notification_once(
        &self,
        ipc: &mut IpcBuffer,
        notification: Notification,
        duration: Duration,
        cancellation_token: [u8; 16],
    );
    fn cancel_notification(&self, ipc: &mut IpcBuffer, cancellation_token: [u8; 16]);
    fn time_since_boot(&self) -> Duration;
}

pub struct SvcTimer {
    pub tsc_freq_mhz: u32,
    pub cap: Endpoint,
}

impl Timer for SvcTimer {
    fn set_notification_once(
        &self,
        ipc: &mut IpcBuffer,
        notification: Notification,
        duration: Duration,
        cancellation_token: [u8; 16],
    ) {
        let (msg, _) = encode_msg(
            ipc,
            &TimeserverMsg::NotifyAfter {
                duration_us: duration.as_micros() as u64,
                cancellation_token,
            },
            DirectTransfer,
            &[notification.cptr()],
        );
        ipc.inner_mut().seL4_Send(self.cap.bits(), msg.into_inner());
    }

    fn cancel_notification(&self, ipc: &mut IpcBuffer, cancellation_token: [u8; 16]) {
        let (msg, _) = encode_msg(
            ipc,
            &TimeserverMsg::Cancel { cancellation_token },
            DirectTransfer,
            &[],
        );
        ipc.inner_mut().seL4_Send(self.cap.bits(), msg.into_inner());
    }

    fn time_since_boot(&self) -> Duration {
        Duration::from_micros(now_cycles() / self.tsc_freq_mhz as u64)
    }
}
