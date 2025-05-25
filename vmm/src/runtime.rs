use core::{
    any::Any,
    cell::{Cell, RefCell},
    future::Future,
    mem::take,
    pin::Pin,
    ptr::NonNull,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    time::Duration,
};

use algorithms::{
    idalloc::{IdAlloc64, IdAlloc64Trait},
    unialloc::UniAllocTrait,
    vm::vcpu::{AbstractVcpu, VcpuFault, VcpuState, VcpuStateMask},
};
use alloc::{
    boxed::Box,
    rc::{Rc, Weak},
};
use intrusive_collections::{KeyAdapter, LinkedList, LinkedListLink, intrusive_adapter, rbtree};
use ipc::{alloc::alloc_and_retype, misc::hw_rng_u64, timer::Timer, untyped::UntypedCap};
use sel4::{
    CapRights, IpcBuffer, ObjectBlueprint,
    cap::{CNode, Notification, Tcb},
};
use x86::vmx::vmcs;

use crate::{
    dump::dump_state,
    vmx::{helper::read_vmcs, vcpu::VmxVcpu},
};

pub type FaultCheck = NonNull<dyn Fn(&VcpuState, &VcpuFault) -> bool + Send + Sync + 'static>;

pub struct EventLoop {
    pit: &'static dyn Timer,
    cspace: CNode,

    next_id: Cell<u64>,
    runnable: RefCell<LinkedList<TaskRunnableAdapter>>,

    sleeping: RefCell<rbtree::RBTree<TaskSleepingAdapter>>,

    waiting: RefCell<[Option<Rc<Task>>; 64]>,
    fault_handlers: RefCell<rbtree::RBTree<TaskFaultAdapter>>,
    vcpu: RefCell<Box<dyn AbstractVcpu<Context = IpcBuffer>>>,
    notif_alloc: RefCell<IdAlloc64<1>>,
    notif_latch: Cell<u64>,

    current: RefCell<Option<Weak<Task>>>,
    current_yield: Cell<bool>,

    notif_cap: Notification,
    fault_active: Cell<Option<FaultKey>>,
    ipcbuf: RefCell<Option<NonNull<IpcBuffer>>>,

    timer_notif_cap: Notification,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct FaultKey {
    reason: u32,
    priority: u8,
    // always `Some` - `None` is used for comparison only
    check: Option<FaultCheck>,
}

struct Task {
    link: LinkedListLink,
    sleep: rbtree::Link,
    sleep_key: Cell<Option<(Duration, u64)>>,
    fault: rbtree::Link,
    fault_key: Cell<Option<FaultKey>>,
    future: RefCell<Pin<Box<dyn Future<Output = ()>>>>,
    waiting: RefCell<heapless::Vec<usize, 4>>,
}

intrusive_adapter!(TaskRunnableAdapter = Rc<Task>: Task { link: LinkedListLink });
intrusive_adapter!(TaskSleepingAdapter = Rc<Task>: Task { sleep: rbtree::Link });
intrusive_adapter!(TaskFaultAdapter = Rc<Task>: Task { fault: rbtree::Link });

impl<'a> KeyAdapter<'a> for TaskSleepingAdapter {
    type Key = (Duration, u64);

    fn get_key(&self, value: &'a Task) -> Self::Key {
        value
            .sleep_key
            .get()
            .expect("KeyAdapter::get_key called on non-keyed sleep")
    }
}

impl<'a> KeyAdapter<'a> for TaskFaultAdapter {
    type Key = FaultKey;

    fn get_key(&self, value: &'a Task) -> Self::Key {
        value
            .fault_key
            .get()
            .expect("KeyAdapter::get_key called on non-keyed fault")
    }
}

impl EventLoop {
    pub fn new(
        ipc: &mut IpcBuffer,
        pit: &'static dyn Timer,
        cspace: CNode,
        vcpu: Box<dyn AbstractVcpu<Context = IpcBuffer>>,
        tcb_cap: Tcb,
        notif_cap: Notification,
        timer_notif_cap: Notification,
        alloc_state: &RefCell<dyn UniAllocTrait<Untyped = UntypedCap>>,
    ) -> Self {
        alloc_and_retype(
            ipc,
            alloc_state,
            cspace,
            &ObjectBlueprint::Notification,
            notif_cap.cptr(),
        )
        .expect("Failed to allocate notification");
        let ret = ipc
            .inner_mut()
            .seL4_TCB_BindNotification(tcb_cap.bits(), notif_cap.bits());
        assert_eq!(ret, 0, "Failed to bind notification to TCB: {}", ret);
        let me = Self {
            next_id: Cell::new(1),
            pit,
            cspace,
            runnable: RefCell::new(LinkedList::new(TaskRunnableAdapter::NEW)),
            sleeping: RefCell::new(rbtree::RBTree::new(TaskSleepingAdapter::NEW)),
            waiting: RefCell::new([const { None }; 64]),
            fault_handlers: RefCell::new(rbtree::RBTree::new(TaskFaultAdapter::NEW)),
            vcpu: RefCell::new(vcpu),
            notif_alloc: RefCell::new(IdAlloc64::new()),
            notif_latch: Cell::new(0),
            current: RefCell::new(None),
            current_yield: Cell::new(false),
            notif_cap,
            fault_active: Cell::new(None),
            ipcbuf: RefCell::new(None),
            timer_notif_cap,
        };
        let timer_badge = me.eval(ipc, || me.create_notification(timer_notif_cap));
        assert_eq!(timer_badge, 1);
        me
    }

    pub fn pit(&self) -> &'static dyn Timer {
        self.pit
    }

    fn current_strong(&self) -> Rc<Task> {
        self.current
            .borrow()
            .as_ref()
            .and_then(|x| x.upgrade())
            .expect("no current task")
    }

    pub fn wait_for_notification(&self, badge: u64) -> impl Future<Output = ()> + Unpin {
        assert!(badge.count_ones() == 1);
        futures::future::poll_fn(move |cx| {
            let evl = EventLoop::from_context(&*cx);
            if evl.did_receive_notification(badge) {
                return Poll::Ready(());
            }
            evl.wake_me_on_notification(badge);
            Poll::Pending
        })
    }

    fn did_receive_notification(&self, badge: u64) -> bool {
        let current = self.notif_latch.get();
        if current & badge != 0 {
            self.notif_latch.set(current & !badge);
            true
        } else {
            false
        }
    }

    fn wake_me_on_notification(&self, badge: u64) {
        let current = self.current_strong();
        let id = badge.trailing_zeros() as usize;
        let mut waiting = self.waiting.borrow_mut();
        if let Some(x) = &waiting[id] {
            if Rc::ptr_eq(x, &current) {
                return;
            }
        }
        assert!(waiting[id].is_none());
        current
            .waiting
            .borrow_mut()
            .push(id)
            .expect("too many notifications");
        waiting[id] = Some(current);
    }

    fn delete_backrefs(&self, task: &Task) {
        if let Some(key) = task.sleep_key.get() {
            let removed = self.sleeping.borrow_mut().find_mut(&key).remove().is_some();
            assert!(removed);
            task.sleep_key.set(None);
        }
        for x in take(&mut *task.waiting.borrow_mut()) {
            let removed = self.waiting.borrow_mut()[x].take();
            assert!(
                removed
                    .as_ref()
                    .map(|x| &**x as *const Task == task as *const Task)
                    .unwrap_or(true)
            );
        }
        if let Some(key) = task.fault_key.get() {
            let removed = self
                .fault_handlers
                .borrow_mut()
                .find_mut(&key)
                .remove()
                .is_some();
            assert!(removed);
            task.fault_key.set(None);
        }
    }

    pub fn spawn(&self, future: impl Future<Output = ()> + 'static) {
        self.runnable.borrow_mut().push_back(Rc::new(Task {
            link: LinkedListLink::new(),
            sleep: rbtree::Link::new(),
            sleep_key: Cell::new(None),
            fault: rbtree::Link::new(),
            fault_key: Cell::new(None),
            future: RefCell::new(Box::pin(future)),
            waiting: Default::default(),
        }));
    }

    pub fn with_ipcbuf<R>(&self, cb: impl FnOnce(&mut IpcBuffer) -> R) -> R {
        let ipcbuf = self.ipcbuf.borrow_mut();
        let mut ipcbuf = ipcbuf.expect("ipcbuf not initialized");
        let ipcbuf = unsafe { ipcbuf.as_mut() };
        cb(ipcbuf)
    }

    pub fn create_notification(&self, child_cap: Notification) -> u64 {
        let index = self
            .notif_alloc
            .borrow_mut()
            .alloc()
            .expect("no more notifications available");
        assert!(index < 64);
        let badge = 1u64 << index;
        let dst = self.cspace.absolute_cptr(child_cap.cptr());
        let src = self.cspace.absolute_cptr(self.notif_cap.cptr());
        let ret = self.with_ipcbuf(|ipc| {
            ipc.inner_mut().seL4_CNode_Mint(
                self.cspace.bits(),
                dst.path().bits(),
                dst.path().depth() as _,
                src.root().bits(),
                src.path().bits(),
                src.path().depth() as _,
                CapRights::write_only().into_inner(),
                badge,
            )
        });
        assert_eq!(ret, 0, "Failed to mint notification");
        badge
    }

    pub fn vcpu(&self) -> &RefCell<Box<dyn AbstractVcpu<Context = IpcBuffer>>> {
        &self.vcpu
    }

    pub fn eval<R>(&self, temp_ipcbuf: &mut IpcBuffer, cb: impl FnOnce() -> R) -> R {
        {
            let mut ipcbuf = self.ipcbuf.borrow_mut();
            assert!(ipcbuf.is_none());
            *ipcbuf = Some(NonNull::from(temp_ipcbuf));
        }
        let ret = cb();
        {
            let mut ipcbuf = self.ipcbuf.borrow_mut();
            assert!(ipcbuf.is_some());
            *ipcbuf = None;
        }
        ret
    }

    pub fn run(&self, new_ipcbuf: &mut IpcBuffer) -> ! {
        {
            let mut ipcbuf = self.ipcbuf.borrow_mut();
            assert!(ipcbuf.is_none());
            *ipcbuf = Some(NonNull::from(new_ipcbuf));
        }

        let timer_token = gen_secret_16b();
        let mut timer_current_deadline: Option<Duration> = None;
        let timer_badge = 1u64;

        let mut hlt = false;

        loop {
            loop {
                let now = self.pit.time_since_boot();
                let task = {
                    let mut runnable = self.runnable.borrow_mut();
                    let mut sleeping = self.sleeping.borrow_mut();

                    let mut cursor = sleeping.cursor_mut();
                    cursor.move_next();
                    while let Some(x) = cursor.get() {
                        let key = x.sleep_key.get().expect("missing sleep key");
                        if key.0 > now {
                            break;
                        }
                        let task = cursor.remove().unwrap();
                        task.sleep_key.set(None);
                        if !task.link.is_linked() {
                            runnable.push_back(task);
                        }
                    }

                    let Some(task) = runnable.pop_front() else {
                        break;
                    };
                    task
                };
                let waker =
                    unsafe { Waker::new(self as *const Self as *const (), &SIMPLE_WAKER_VTABLE) };
                let mut cx = Context::from_waker(&waker);
                self.delete_backrefs(&task);
                self.current_yield.set(false);
                self.current.borrow_mut().replace(Rc::downgrade(&task));
                let _ = task.future.borrow_mut().as_mut().poll(&mut cx);
                self.current.borrow_mut().take();

                if self.current_yield.get() {
                    self.runnable.borrow_mut().push_back(task);
                }
            }

            if self.did_receive_notification(timer_badge) {
                timer_current_deadline = None;
            }

            let need_update_timer = if let Some(x) = self.sleeping.borrow().front().get() {
                timer_current_deadline.is_none()
                    || x.sleep_key.get().unwrap().0 < timer_current_deadline.unwrap()
            } else {
                false
            };

            if need_update_timer {
                if timer_current_deadline.is_some() {
                    self.with_ipcbuf(|ipc| self.pit.cancel_notification(ipc, timer_token));
                }
                let deadline = self
                    .sleeping
                    .borrow()
                    .front()
                    .get()
                    .unwrap()
                    .sleep_key
                    .get()
                    .unwrap()
                    .0;
                timer_current_deadline = Some(deadline);
                let now = self.pit.time_since_boot();
                let duration = deadline.saturating_sub(now).max(Duration::from_micros(1));
                self.with_ipcbuf(|ipc| {
                    self.pit
                        .set_notification_once(ipc, self.timer_notif_cap, duration, timer_token)
                });
            }

            if hlt && self.vcpu.borrow_mut().external_interrupt_pending() {
                hlt = false;
            }

            let sender = if self.fault_active.get().is_some() || hlt {
                let (_, sender) =
                    self.with_ipcbuf(|ipc| ipc.inner_mut().seL4_Wait(self.notif_cap.bits()));
                sender
            } else {
                let mut vcpu = self.vcpu.borrow_mut();
                let (fault, sender) = self.with_ipcbuf(|ipc| vcpu.enter(ipc));
                match fault {
                    true if vcpu.fault().reason == 7 => {
                        // interrupt window
                    }
                    true if vcpu.fault().reason == 12 => {
                        // HLT exit
                        hlt = true;
                        // println!("HLT exit @ IP: {:#x}", vcpu.state().eip);
                        vcpu.state_mut().eip += vcpu.fault().instruction_len;
                        self.with_ipcbuf(|ipc| vcpu.commit_state(ipc, VcpuStateMask::EIP));
                    }
                    true => {
                        let state = vcpu.state();
                        let fault = vcpu.fault();
                        // println!("fault: {:x?} {:x?}", fault, state);
                        let mut fault_handlers = self.fault_handlers.borrow_mut();
                        let mut cursor = fault_handlers.lower_bound_mut(
                            intrusive_collections::Bound::Excluded(&FaultKey {
                                reason: fault.reason as u32,
                                priority: 0,
                                check: None,
                            }),
                        );
                        let mut handler = None;
                        while let Some(x) = cursor.get() {
                            if x.fault_key.get().unwrap().reason != fault.reason as u32 {
                                break;
                            }
                            let check = unsafe {
                                x.fault_key.get().unwrap().check.unwrap_unchecked().as_ref()
                            };
                            if check(state, fault) {
                                handler = Some(cursor.remove().unwrap());
                                break;
                            }
                            cursor.move_next();
                        }

                        // is there a higher-priority catch-all handler?
                        // NOTE: at this point `handler.fault_key` is not yet removed. Do not return.
                        cursor = fault_handlers.lower_bound_mut(
                            intrusive_collections::Bound::Excluded(&FaultKey {
                                reason: core::u32::MAX,
                                priority: 0,
                                check: None,
                            }),
                        );
                        while let Some(x) = cursor.get() {
                            let check = unsafe {
                                x.fault_key.get().unwrap().check.unwrap_unchecked().as_ref()
                            };
                            if let Some(old_handler) = &handler {
                                if x.fault_key.get().unwrap().priority
                                    >= old_handler.fault_key.get().unwrap().priority
                                {
                                    break;
                                }
                            }

                            if check(state, fault) {
                                let old_handler = handler.replace(cursor.remove().unwrap());
                                if let Some(old_handler) = old_handler {
                                    fault_handlers.insert(old_handler);
                                }
                                break;
                            }
                            cursor.move_next();
                        }

                        let Some(handler) = handler else {
                            println!("unhandled fault: {:?}", fault);
                            self.with_ipcbuf(|ipc| dump_state(ipc, &mut **vcpu));
                            self.with_ipcbuf(|ipc| {
                                if let Some(vcpu) = (&**vcpu as &dyn Any).downcast_ref::<VmxVcpu>()
                                {
                                    let interruption_info = read_vmcs(
                                        vcpu.vcpu_cap,
                                        ipc,
                                        vmcs::ro::VMEXIT_INTERRUPTION_INFO.into(),
                                    );
                                    println!("Interrupt info: {:#x}", interruption_info);
                                }
                            });
                            panic!("unhandled fault");
                        };
                        let fault_key = handler.fault_key.take().unwrap();
                        self.fault_active.set(Some(fault_key));
                        self.runnable.borrow_mut().push_back(handler);
                    }
                    false => {}
                }
                if sender == 0 {
                    continue;
                }
                sender
            };

            self.notif_latch.set(self.notif_latch.get() | sender);

            // if sender != 1 {
            //     println!("interesting sender: {:x}", sender);
            // }
            for i in 0..64 {
                if sender & (1 << i) != 0 {
                    if let Some(task) = self.waiting.borrow_mut()[i].take() {
                        if !task.link.is_linked() {
                            self.runnable.borrow_mut().push_back(task);
                        }
                    }
                }
            }
        }
    }

    pub fn from_context<'a>(context: &Context<'a>) -> &'a Self {
        let waker = context.waker();
        if waker.vtable() as *const _ != &SIMPLE_WAKER_VTABLE {
            panic!("unexpected waker type");
        }
        unsafe { &*(waker.data() as *const Self) }
    }

    pub fn ack_fault(&self) {
        self.fault_active.set(None);
    }
}

pub fn sleep(duration: Duration) -> impl Future<Output = ()> + Unpin {
    let mut target_time: Option<Duration> = None;

    futures::future::poll_fn(move |cx| {
        let evl = EventLoop::from_context(&*cx);
        if target_time.is_none() {
            target_time = Some(evl.pit.time_since_boot() + duration);
        }
        let target_time = target_time.unwrap();

        if evl.pit.time_since_boot() >= target_time {
            return Poll::Ready(());
        }
        let key = (target_time, evl.next_id.get());
        evl.next_id.set(evl.next_id.get() + 1);
        let current = evl.current_strong();

        // Replace the entry if this sleep request has a sooner deadline
        if let Some(old_key) = current.sleep_key.get() {
            if key.0 < old_key.0 {
                let removed = evl
                    .sleeping
                    .borrow_mut()
                    .find_mut(&old_key)
                    .remove()
                    .is_some();
                assert!(removed);
                current.sleep_key.set(None);
            }
        }

        if current.sleep_key.get().is_none() {
            current.sleep_key.set(Some(key));
            evl.sleeping.borrow_mut().insert(current.clone());
        }

        Poll::Pending
    })
}

pub fn wait_for_fault(
    priority: u8,
    reason: u32,
    check: &'static (dyn Fn(&VcpuState, &VcpuFault) -> bool + Send + Sync + 'static),
) -> impl Future<Output = ()> {
    let check = NonNull::from(check);
    let our_key = FaultKey {
        reason,
        priority,
        check: Some(NonNull::from(check)),
    };
    futures::future::poll_fn(move |cx| {
        let evl = EventLoop::from_context(&*cx);
        if let Some(key) = evl.fault_active.get() {
            if our_key == key {
                return Poll::Ready(());
            }
        }

        let current = evl.current_strong();
        let mut fault_handlers = evl.fault_handlers.borrow_mut();
        if let Some(old_key) = current.fault_key.get() {
            fault_handlers
                .find_mut(&old_key)
                .remove()
                .expect("old_key not found in fault_handlers");
        }
        current.fault_key.set(Some(our_key));
        fault_handlers.insert(current.clone());
        Poll::Pending
    })
}

#[allow(dead_code)]
pub fn yield_now() -> impl Future<Output = ()> + Unpin {
    let mut did_yield = false;
    futures::future::poll_fn(move |cx| {
        let evl = EventLoop::from_context(&*cx);
        if !did_yield {
            evl.current_yield.set(true);
            did_yield = true;
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
}

unsafe fn waker_clone(_: *const ()) -> RawWaker {
    panic!("SimpleWaker cannot be cloned")
}

unsafe fn waker_wake(_: *const ()) {}

unsafe fn waker_wake_by_ref(_: *const ()) {}

unsafe fn waker_drop(_: *const ()) {}

const SIMPLE_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

fn gen_secret_16b() -> [u8; 16] {
    let mut output = [0u8; 16];
    output[0..8].copy_from_slice(&hw_rng_u64().to_le_bytes());
    output[8..16].copy_from_slice(&hw_rng_u64().to_le_bytes());
    output
}
