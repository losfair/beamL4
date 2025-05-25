#!/bin/bash

set -e
cd "$(dirname $0)"

rm -rf iso
mkdir -p iso/boot/grub

cat > iso/boot/grub/grub.cfg <<EOF
set timeout=0
set default=0

menuentry "app" {
    multiboot /boot/kernel.elf
    module /boot/app.elf
    boot
}
EOF

cp "./kbuild/install/bin/kernel.elf" ./iso/boot/kernel.elf
cp ./target/x86_64-sel4/release/beaml4-init.elf ./iso/boot/app.elf
grub-mkrescue -d /usr/lib/grub/i386-pc -o boot.iso iso
