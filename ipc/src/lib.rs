#![no_std]
#![allow(incomplete_features)]
#![feature(const_type_name, generic_const_exprs)]

extern crate alloc as alloc_;

#[macro_use]
pub mod logging;

pub mod alloc;
pub mod cap_blackhole;
pub mod conventions;
pub mod dbgsvc;
pub mod host_paging;
pub mod misc;
pub mod msgbuf;
pub mod timer;
pub mod timesvc;
pub mod untyped;
pub mod userfault;
pub mod virtiosvc;
pub mod vmmsvc;
pub mod x86_ioport;
