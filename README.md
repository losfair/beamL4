# beaml4

An seL4-based x86-64 hypervisor supporting both Intel VT-x hardware virtualization and shadow page table paravirtualization.

beaml4 currently requires [a 19-line patch to seL4](https://github.com/losfair/seL4/commit/eb482a6f1fb96603f7b1bc196b7cdb500e0c1daa) to work.

## Overview

beaml4 is a microkernel-based hypervisor built on the seL4 microkernel that provides two distinct virtualization modes:

- **VT-x Mode**: Hardware-accelerated virtualization using Intel's VT-x technology
- **Paravirtualization Mode**: Software-based virtualization using shadow page tables that doesn't require hardware virtualization features

The hypervisor is designed as a collection of cooperating user-space services running on seL4, providing strong isolation and security guarantees.

## Architecture

### Core Components

- **beaml4-init**: Main initialization service that bootstraps the system and manages VM lifecycle
- **vmmserver**: Virtual machine monitor that handles VM execution and fault emulation
- **virtioserver**: VirtIO device emulation server for storage, network, and other paravirtualized devices
- **timeserver**: Centralized time management service
- **logserver**: System-wide logging service
- **dbgserver**: Debug interface and shell

### Virtualization Implementations

#### VT-x Hardware Virtualization (`vmm/src/vmx/`)
- Uses Intel VT-x VMCS (Virtual Machine Control Structure)
- Hardware-accelerated guest execution
- Minimal VM exits for better performance
- Direct hardware feature passthrough capabilities

#### Paravirtualization (`vmm/src/pv/`)
- Software TLB (Translation Lookaside Buffer) management
- Shadow page table implementation
- **Static patch point system** - replaces specific privileged instructions in guest kernel text with invalid opcodes (0x0e) or syscalls, rather than full dynamic binary translation
- No dependency on hardware virtualization features

### Service Architecture

The system uses seL4's capability-based IPC for communication between services:

- **IPC Library** (`ipc/`): Provides typed message passing, capability management, and service protocols
- **Memory Management**: Unified allocator with support for different page sizes and device memory
- **Host Paging**: Host-side memory management and page table operations
- **Event Loop**: Asynchronous task execution framework for handling VM faults and device events

## Building

### Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- seL4 kernel sources
- CMake and Ninja build system
- QEMU for simulation

### Build Steps

1. **Build the seL4 kernel**:
   ```bash
   ./mkkernel.sh
   ```

2. **Build the hypervisor**:
   ```bash
   cargo build --release
   ```

3. **Create bootable ISO**:
   ```bash
   ./mkiso.sh
   ```

## Running

### Simulation
```bash
./simulate.sh
```

This launches QEMU with KVM acceleration, using a Q35 machine with:
- 2 CPU cores
- 512MB RAM  
- VirtIO SCSI storage
- VirtIO network interface

### Testing
```bash
./test.sh
```

Runs the algorithm test suite.

## Features

- **Dual Virtualization Modes**: Hardware VT-x and software paravirtualization
- **VirtIO Support**: Full VirtIO device stack for storage, networking, and other devices
- **Memory Management**: Advanced memory allocation with support for large pages and device memory
- **Real-time Capabilities**: Precise timing and scheduling via dedicated time service
- **Security**: Capability-based isolation using seL4's formal verification
- **Debugging**: Integrated debug server with shell interface
- **Multi-VM Support**: Ability to run multiple guest VMs simultaneously

## Technical Details

### Paravirtualization Patch Point System

The paravirtualization mode uses a **static patch point approach** rather than full dynamic binary translation:

1. **Static Analysis**: During guest kernel loading (`vmmserver/src/loader.rs:347`), the ELF loader scans executable sections for privileged instructions
2. **Patch Point Detection**: Identifies specific instructions that need virtualization:
   - `VMCALL` - replaced with `syscall + nop`
   - `PUSHFQ/POPFQ` - flag manipulation
   - `CPUID` - CPU identification
   - `SIDT` - interrupt descriptor table access
   - `IRETQ` - interrupt return
3. **Static Patching**: Replaces detected instructions with invalid opcodes (`0x0e`) or equivalent sequences
4. **Runtime Emulation**: When the guest hits these invalid opcodes, it triggers a fault that the hypervisor catches and emulates

This approach provides the benefits of paravirtualization without the complexity and overhead of full dynamic binary translation, making it suitable for real-time and security-critical workloads.

### Userspace Component Architecture

#### beaml4-init (`beaml4-init/src/main.rs:66`)
The **root task** and system orchestrator that runs with maximum privileges:

- **Process Management**: Spawns and manages all other system services using embedded ELF binaries
- **Resource Allocation**: Manages the unified allocator and capability space allocation
- **VM Lifecycle**: Handles VM creation, destruction, reboot, and configuration changes
- **Hardware Initialization**: Sets up ACPI, PCI device discovery, and VirtIO device enumeration
- **IPC Coordination**: Provides the central hypervisor channel for inter-service communication

Key responsibilities:
- Memory management via `AllocState` with 256KB heap
- Service lifecycle (logserver, timeserver, virtioserver, vmmserver, dbgserver)
- VM array management (supports up to 16 VMs)
- Hardware resource distribution (IRQ vectors, IO ports, memory regions)

#### vmmserver (`vmmserver/src/main.rs:74`)
The **Virtual Machine Monitor** that provides the core virtualization environment:

- **Guest Execution**: Manages VCPU state and handles VM entry/exit for both VT-x and PV modes
- **Memory Management**: Implements guest paging with identity mapping and dynamic memory allocation
- **Fault Handling**: Provides async event loop for handling guest faults (I/O, exceptions, hypercalls)
- **ELF Loading**: Loads guest kernels and applies PV patch points during boot

Technical details:
- 128KB heap with dual allocator design
- Two-level capability table (32/32 bit split) for scalability
- Dedicated L0 CNode for guest page table management
- Event-driven architecture with async fault handlers

#### virtioserver (`virtioserver/src/main.rs:44`)
**VirtIO device emulation** server providing paravirtualized I/O:

- **Device Emulation**: Full VirtIO 1.0 specification implementation
- **Memory Management**: Handles guest-host memory mapping for DMA operations
- **Queue Processing**: Processes virtqueue descriptors and manages device state
- **Performance Optimization**: Uses direct memory mapping and zero-copy operations

Key features:
- 2MB heap for buffer management
- Support for multiple virtqueues per device
- Async pipeline architecture for request processing
- Direct guest memory access via user fault handling

#### timeserver (`timeserver/src/main.rs:50`)
**Centralized timing service** using x86 PIT (Programmable Interval Timer):

- **Timer Scheduling**: Provides microsecond-precision timing using TSC and PIT
- **Event Management**: Maintains a timing wheel for efficient timer management
- **Cancellation Support**: Allows timer cancellation with unique tokens
- **Interrupt Handling**: Uses PIT interrupts for timer event delivery

Implementation:
- Scapegoat tree data structure for O(log n) timer operations
- Capability-based notification system for timer delivery
- Dynamic PIT register updates for optimal interrupt timing

#### logserver (`logserver/src/main.rs:39`)
**System logging service** with dual output (serial + VGA):

- **Output Multiplexing**: Simultaneously outputs to serial console and VGA framebuffer  
- **Ring Buffer**: Lock-free ring buffer for high-performance log message queuing
- **Multi-threaded**: Separate thread for VGA rendering to avoid blocking producers
- **Serial Interface**: Direct serial port communication for remote debugging

Features:
- 80x25 text mode VGA rendering
- Atomic ring buffer operations
- Blue background VGA theme
- Real-time serial output

#### dbgserver (`dbgserver/src/main.rs:51`)
**Interactive debugging interface** with keyboard and shell support:

- **Shell Interface**: Command-line interface for system introspection and control
- **Keyboard Handling**: PS/2 keyboard driver with US layout support
- **Hypervisor Control**: Direct communication with VMs via hypervisor channel
- **Serial Integration**: Bidirectional serial communication for remote access

Capabilities:
- PC keyboard scancode translation
- Interactive command processing
- VM control operations (reboot, kill, mode switching)
- System status monitoring

## Core Algorithms (`algorithms/`)

The algorithms crate provides the fundamental data structures and abstractions used throughout the hypervisor:

### Unified Allocator (`unialloc.rs`)
A **sophisticated memory allocator** that manages seL4 untyped memory capabilities:

- **Two-tier Design**: Separates normal memory and device memory into different allocation pools
- **BTreeMap Storage**: 
  - Normal memory: `(size_bits, paddr) -> cap` for efficient size-based allocation
  - Device memory: `paddr -> (cap, size_bits)` for address-based device mapping
- **Capability Management**: Integrates with ID allocator for capability slot management
- **Splitting Algorithm**: Supports splitting large untyped capabilities into smaller ones on-demand
- **Context Abstraction**: Generic over capability types via `AbstractUntyped` trait

Key features:
- O(log n) allocation by size or specific physical address
- Automatic capability recycling and splitting
- Support for both boxed and static allocation patterns
- Device memory isolation for MMIO regions

### ID Allocator (`idalloc.rs`)
A **multi-level radix tree** for efficient capability slot allocation:

- **Radix Structure**: Uses base-64 radix tree with configurable depth (2-4 levels typical)
- **Bitmap Tracking**: Each node contains a 64-bit allocation bitmap
- **Hierarchical Design**: Propagates allocation state up the tree for fast searches
- **Capacity**: 
  - 3 levels: 262,144 slots
  - 4 levels: 16,777,216 slots
- **Offset/Limit Wrapper**: Supports bounded allocation ranges via `IdAlloc64OffsetLimit`

Algorithm complexity:
- Allocation: O(depth) - typically O(1) to O(4)
- Free: O(depth)  
- Contains check: O(depth)

### Page Table Manager (`pagetable.rs`)
**Generic page table management** abstraction supporting arbitrary architectures:

- **Level-based Design**: Configurable number of page table levels and page sizes
- **Pool Management**: Maintains pools of unused page table structures for recycling
- **Lazy Allocation**: Only allocates intermediate page tables when needed
- **Mapping Tracking**: BTreeMap tracks which virtual addresses have allocations
- **Error Handling**: Comprehensive error types for debugging page table issues

Template parameters:
- `NUM_LEVELS`: Number of page table levels (e.g., 4 for x86-64)
- `LEVEL_SIZE_BITS`: Bits per level (e.g., 9 for x86-64 512-entry tables)
- `LEAF_SIZE_BITS`: Base page size (e.g., 12 for 4KB pages)

### VCPU Abstractions (`vm/vcpu.rs`)
**Hardware-agnostic virtualization** primitives:

- **State Management**: Complete x86-64 register set with change tracking via `VcpuStateMask`
- **Fault Handling**: Unified fault representation for both VT-x and PV modes
- **Interrupt Bitmap**: 256-bit bitmap for pending interrupt tracking
- **Exception Injection**: Abstract interface for injecting guest exceptions
- **Trait-based Design**: `AbstractVcpu` trait allows multiple VCPU implementations

Key data structures:
- `VcpuState`: Complete architectural state with validity tracking
- `VcpuFault`: VM exit/fault information (reason, qualification, guest physical address)
- `InterruptBitmap`: Efficient pending interrupt tracking
- `VcpuStateMask`: Bitflags for tracking which registers need synchronization

### Instruction Decoding (`vm/vcpu_decode.rs`)
**VM exit instruction decoding** utilities:

- **Control Register Access**: Decodes CR0/CR3/CR4 access attempts
- **I/O Port Access**: Decodes IN/OUT instructions with size and direction
- **Register Mapping**: Maps x86 register encodings to `VcpuState` fields
- **Qualification Parsing**: Extracts detailed information from hardware qualification values

## VMM Implementation (`vmm/`)

The VMM crate provides the core virtualization engine with two distinct backends sharing common infrastructure:

### VMX Backend (`vmm/src/vmx/`)
**Intel VT-x hardware virtualization** using Virtual Machine Control Structure (VMCS):

#### Architecture
- **seL4 VCPU Object**: Creates hardware VCPU using seL4's x86 VCPU capability
- **VMCS Configuration**: Sets up guest execution environment per PVH specification
- **VM Entry/Exit**: Uses custom `seL4_VMEnter` syscall with efficient fault reporting
- **Direct Execution**: Guest code runs natively with minimal hypervisor intervention

#### Implementation Details (`vmx/vcpu.rs:43`)
- **Guest State Setup**: Configures 32-bit PVH environment (CR0=0x1, segments, descriptors)
- **Control Structure**: Manages execution controls, exception bitmap, I/O port access
- **Fault Handling**: Receives detailed fault information (reason, qualification, guest registers)
- **Performance Tracking**: Monitors VM execution time and fault frequency

Key features:
- Hardware acceleration with minimal VM exits
- RTC passthrough for real-time workloads
- TSC scaling and timer integration
- Exception injection and interrupt delivery

### PV Backend (`vmm/src/pv/`)
**Software-based paravirtualization** with shadow page tables and binary patching:

#### Software TLB (`pv/swtlb.rs:56`)
**Hierarchical shadow page table management**:

- **4-level Structure**: Mirrors x86-64 page tables (PML4 → PDPT → PD → PT)
- **Pool Management**: Maintains free pools for each level with configurable limits
- **Capability Mapping**: Each page table backed by seL4 capability in sub-cnode
- **Lazy Population**: Allocates page tables on-demand during guest page faults
- **Shootdown Support**: Efficient TLB invalidation across address ranges

Algorithm:
```
Max Active: [512 PDPTs, 512 PDs, 2048 PTs, 16384 Pages]
Coverage:   [512GB,    1GB,      2MB,      4KB per structure]
```

#### Page Table Walker (`pv/ptw.rs:10`)
**Guest memory access and translation**:

- **Virtual-to-Physical**: Walks guest page tables to resolve addresses
- **Permission Tracking**: Maintains read/write permissions through translation
- **Identity Mapping**: Maps guest physical to host virtual addresses
- **Memory Safety**: Validates all guest memory accesses within bounds

#### PV VCPU (`pv/vcpu.rs:65`)
**Software CPU virtualization**:

- **State Emulation**: Maintains complete x86-64 architectural state in software
- **Patch Point Execution**: Handles invalid opcode faults from static patches
- **System Call Interface**: Uses seL4 fault handling for privileged instructions
- **Shared Memory**: Guest-hypervisor communication via mapped shared page

Key components:
- **MSR Emulation**: Software emulation of model-specific registers
- **Privilege Levels**: CPL tracking and validation for security
- **Interrupt Injection**: Software interrupt delivery mechanism
- **Context Switching**: Full architectural state save/restore

### Common Infrastructure

#### Event Loop (`runtime.rs:36`)
**Async task scheduling and fault management**:

- **Cooperative Multitasking**: Rust async/await-based task execution
- **Fault Routing**: Priority-based fault handler registration and dispatch
- **Timer Integration**: Sleep/wake functionality using PIT timer
- **Notification Management**: seL4 notification-based event delivery

Data structures:
- **Task Trees**: RB-trees for sleeping tasks and fault handlers
- **Runnable Queue**: Linked list of ready-to-run tasks
- **Priority System**: 8-bit priority levels for fault handler precedence

#### Fault Emulation (`fault.rs`)
**Device and instruction emulation**:

- **I/O Port Emulation**: Serial console, keyboard, PCI configuration space
- **Control Register Handling**: CR0/CR3/CR4 access emulation
- **CPUID Emulation**: CPU feature reporting to guests
- **Exception Injection**: Delivers #GP, #UD, and other exceptions to guests

#### VM Paging (`paging.rs:33`)
**Guest memory management abstraction**:

- **Dual Mode Support**: Handles both EPT (VT-x) and shadow pages (PV)
- **Memory Regions**: Low memory (0-256MB) and high memory (128GB+) regions
- **Page Table Management**: Generic page table allocation and mapping
- **ASID Management**: Address space identifier assignment

## Guest Support

The hypervisor is only tested with the [Nanos](https://github.com/nanovms/nanos)
unikernel as the guest OS.

## Configuration

VM configuration is handled through the initialization service, supporting:
- Memory allocation (dynamic sizing based on available memory)
- Virtualization mode selection (VT-x vs paravirtualization)
- VirtIO device assignment
- CPU affinity and priority settings

## Development

The codebase is written in Rust with extensive use of:
- `no_std` for microkernel compatibility
- Zero-copy serialization with `rkyv`
- Lock-free data structures where possible
- Formal verification compatible with seL4

Key directories:
- `vmm/`: Core virtualization logic
- `algorithms/`: Memory management and data structures
- `ipc/`: Inter-process communication library
- `examples/`: Sample applications and benchmarks

## License

[License information would go here]