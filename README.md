# RuSTMtest

Test STM32F4 assembly projects on your host.

This program is built for assisting the unit testing of STM32F4 assembly projects. It will load an ARM 32-bit little-endian ELF executable into an ARM emulator's memory space corresponding to an STM32F401, then load one or more test scripts that setup register values, call a symbol, and check register contents after the function defined by the symbol returns.

## Building

![CI](https://github.com/codebje/rustmtest/workflows/CI/badge.svg)

```
cargo build
```

## Running

```
cargo run <elf file> <test script> [<test script> ...]
```

## Test script syntax

The test scripts are extremely basic. There are four sections, declared with the section name followed by a colon. The order of the sections is fixed, and all of them are required.

  - `test:` defines the name of the test. The test's name is output during test execution, and is the remainder of the line.
  - `setup:` defines the initial register values. Registers may be specified in decimal, hex, or binary. Order of registers
  doesn't matter, but only r0 to r7 are recognised.
  - `call:` selects the target symbol to execute. The symbol _must_ be defined as a `%function`, and may be local or global.
  - `check:` defines the expected register values on exit.

The symbol can be any string, terminated by whitespace. In general, whitespace is ignored, so you are free to use blank lines, indentation, and spacing for readability.

The following is an example test case for my STM32F4 memory driver, which serves as RAM/ROM for a Z180 processor. The pin wiring puts an 8-bit address into port B pins 0:1, 5:10. The function should take those bits and pack them, then add on the relevant base address for RAM or ROM contents. In the example, the address is `0b10111001`, with the bit pattern `0b011` in the unused three bits. This corresponds to `185` or `0xb9`, and is in RAM (selected by the MSB) based at `0x20000000`. `r1` is cleared on exit to indicate that it is a RAM address.

```
test: Memory Address decode

setup:
    r0 = 0b10111011101

call: memaddr

check:
    r0 = 0x200000b9
    r1 = 0
```
