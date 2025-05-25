#![no_std]
#![allow(incomplete_features)]
#![feature(generic_const_exprs, new_zeroed_alloc)]

extern crate alloc;

#[macro_use]
extern crate ipc;

pub mod dump;
pub mod fault;
pub mod paging;
pub mod pv;
pub mod runtime;
pub mod vapic;
pub mod virtio;
pub mod vmx;
pub mod x86_exception;
