# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

beaml4 is a seL4-based x86-64 hypervisor supporting both Intel VT-x hardware virtualization and shadow page table paravirtualization. The system is architected as a collection of cooperating user-space services running on the seL4 microkernel.

**Important**: beaml4 requires [a 19-line patch to seL4](https://github.com/losfair/seL4/commit/eb482a6f1fb96603f7b1bc196b7cdb500e0c1daa) to work.

For comprehensive documentation including technical details, algorithms, and component architecture, see [README.md](README.md).

## Build and Development Commands

### Building
```bash
# Build the seL4 kernel
./mkkernel.sh

# Build the hypervisor (run from project root)
cargo build --release

# Create bootable ISO
./mkiso.sh
```

### Testing
```bash
# Run algorithm tests
./test.sh

# Run specific algorithm tests
cargo test --target x86_64-unknown-linux-gnu -p algorithms -Z build-std="" -- <test_name>
```

### Running
```bash
# Launch in QEMU with KVM
./simulate.sh
```

## Architecture Overview

### Core System Design
The hypervisor follows a **microservice architecture** where each component runs as an isolated seL4 process:

- **beaml4-init**: Root task orchestrating system bootstrap, resource allocation, and VM lifecycle
- **vmmserver**: Core VMM providing virtualization (VT-x or PV mode)
- **virtioserver**: VirtIO device emulation for paravirtualized I/O
- **timeserver**: Centralized timing using x86 PIT with microsecond precision
- **logserver**: System logging with dual output (serial + VGA)
- **dbgserver**: Interactive debugging with keyboard/shell support

### Key Algorithms (`algorithms/`)
- **UniAlloc**: Sophisticated two-tier memory allocator managing seL4 untyped capabilities
- **IdAlloc**: Multi-level radix tree for efficient capability slot allocation (base-64, O(depth) ops)
- **PageTableManager**: Generic page table abstraction supporting arbitrary architectures
- **VCPU Abstractions**: Hardware-agnostic virtualization primitives

### VMM Backends (`vmm/`)

#### VMX Backend (`vmm/src/vmx/`)
- Uses seL4 VCPU capabilities with Intel VT-x VMCS
- Custom `seL4_VMEnter` syscall for efficient VM entry/exit (~1000 cycles)
- Hardware acceleration with minimal hypervisor intervention
- Supports RTC passthrough for real-time workloads

#### PV Backend (`vmm/src/pv/`)
- **Software TLB**: 4-level shadow page tables with pool management
- **Static Patch Points**: Replaces privileged instructions with invalid opcodes (0x0e)
- **Page Table Walker**: Guest memory translation with bounds checking
- No hardware virtualization dependency

### Communication Architecture
- **IPC Library** (`ipc/`): Typed message passing, capability management, service protocols
- **Event Loop**: Async/await-based task scheduling with priority-based fault routing
- **Capability Management**: seL4 capabilities used for all inter-service communication

## Development Guidelines

### Memory Management
- All components use unified allocators (UniAlloc) for seL4 untyped memory
- Capability slots managed via IdAlloc with configurable depth (2-4 levels)
- Pool-based recycling for page tables and other paging structures

### Virtualization Modes
- **VT-x Mode**: Use when hardware support available, optimal for CPU-intensive workloads
- **PV Mode**: Use when hardware VT-x unavailable, suitable for I/O-intensive workloads
- Mode selection handled in `vmmserver` based on configuration

### Static Patch Point System (PV Mode)
- ELF loader (`vmmserver/src/loader.rs:347`) scans executable sections for privileged instructions
- Patches applied at load time: `VMCALL` → `syscall + nop`, others → `0x0e` invalid opcode
- Runtime emulation triggered by invalid opcode faults

### Fault Handling
- Priority-based fault routing system (0-255 priority levels)
- Async fault handlers registered in event loop
- Common emulation: serial I/O, CPUID, control registers, I/O ports

### Testing Strategy
- Algorithm tests focus on core data structures (IdAlloc, UniAlloc, PageTableManager)
- Integration testing via QEMU simulation
- No unit tests for system services (seL4 environment required)

## Key Configuration

### Memory Layout
- Guest low memory: 0-256MB
- Guest high memory: 128GB+ region
- Host dynamic mappings: 0x1_0000_0000 - 0x1_4000_0000
- Identity mapping regions for guest physical memory

### Capability Management
- 2-level capability tables (32/32 bit split) for scalability
- Static capability base: 0xf000
- Dynamic allocation via IdAlloc with offset/limit wrappers

## Codebase Structure

### Workspace Layout
```
beaml4/
├── algorithms/          # Core data structures and abstractions
│   ├── src/idalloc.rs      # Multi-level radix tree for capability slots
│   ├── src/unialloc.rs     # Two-tier memory allocator for seL4 untyped caps
│   ├── src/pagetable.rs    # Generic page table management
│   └── src/vm/             # VCPU abstractions and instruction decoding
├── beaml4-init/        # Root task and system orchestrator
├── vmmserver/          # Virtual machine monitor
│   ├── src/loader.rs       # ELF loading and patch point application
│   ├── src/vmservice.rs    # VM lifecycle management
│   └── src/hypercall.rs    # Guest-hypervisor communication
├── virtioserver/       # VirtIO device emulation
│   ├── src/pipeline.rs     # VirtIO request processing pipeline
│   └── src/virtq.rs        # Virtqueue management
├── vmm/                # Core virtualization engine
│   ├── src/vmx/            # Intel VT-x backend
│   ├── src/pv/             # Paravirtualization backend
│   ├── src/runtime.rs      # Async event loop and task scheduling
│   ├── src/fault.rs        # Device and instruction emulation
│   └── src/paging.rs       # Guest memory management
├── ipc/                # Inter-process communication library
├── timeserver/         # Centralized timing service
├── logserver/          # System logging
└── dbgserver/          # Interactive debugging
```

### Key Files for Understanding the System
- `README.md` - Comprehensive technical documentation
- `beaml4-init/src/main.rs:66` - System bootstrap and service orchestration
- `vmmserver/src/main.rs:74` - VM monitor initialization and management
- `vmmserver/src/loader.rs:347` - Static patch point implementation
- `vmm/src/vmx/vcpu.rs:43` - VT-x VCPU implementation
- `vmm/src/pv/vcpu.rs:65` - Paravirtualization VCPU implementation
- `vmm/src/pv/swtlb.rs:56` - Software TLB management
- `vmm/src/runtime.rs:36` - Async event loop architecture
- `algorithms/src/unialloc.rs` - Memory allocator design
- `algorithms/src/idalloc.rs` - Capability slot allocation
