#![no_std]
#![allow(incomplete_features)]
#![feature(generic_const_exprs, new_zeroed_alloc, linked_list_retain)]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod idalloc;
pub mod pagetable;
pub mod unialloc;
pub mod vm;
