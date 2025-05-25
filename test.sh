#!/bin/bash

exec cargo test --target x86_64-unknown-linux-gnu -p algorithms -Z build-std="" -- $@
