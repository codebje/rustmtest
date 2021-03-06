mod lex;
mod testcase;

extern crate exitcode;
extern crate unicorn;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::fmt;
use goblin::elf::{Elf, Sym};
use std::env;
use std::fs;
use std::io;
use std::io::Cursor;
use std::path::Path;
use unicorn::{Cpu, CpuARM, RegisterARM};

use crate::testcase::*;

const FLASH_BASE: u64 = 0x08000000;
const FLASH_SIZE: usize = 0x00040000;
const SRAM_BASE: u64 = 0x20000000;
const SRAM_SIZE: usize = 0x00010000;
const HARNESS_SIZE: usize = 0x1000;
const HARNESS_BASE: u64 = 0xFFFF0000;

#[derive(Debug)]
enum Error {
    WrongElf(),
    Goblin(goblin::error::Error),
    Unicorn(unicorn::Error),
    IO(io::Error),
    UTF8(std::str::Utf8Error),
    LexError(lex::LexErrorKind),
    TestMismatch(RegisterARM, i32, i32),
}

impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Error {
        Error::Goblin(err)
    }
}

impl From<unicorn::Error> for Error {
    fn from(err: unicorn::Error) -> Error {
        Error::Unicorn(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Error {
        Error::UTF8(err)
    }
}

impl From<(lex::LexErrorKind, &str)> for Error {
    fn from((err, _str): (lex::LexErrorKind, &str)) -> Error {
        Error::LexError(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::WrongElf() => write!(fmt, "Invalid ELF file: 32-bit little-endian ARM expected"),
            Error::Goblin(ref err) => write!(fmt, "{}", err),
            Error::Unicorn(ref err) => write!(fmt, "{}", err),
            Error::IO(ref err) => write!(fmt, "{}", err),
            Error::UTF8(ref err) => write!(fmt, "{}", err),
            Error::LexError(ref err) => write!(fmt, "{}", err),
            Error::TestMismatch(reg, got, want) => {
                write!(fmt, "{:?}=0x{:08x} not 0x{:08x}", reg, got, want)
            }
        }
    }
}

fn load_elf(buffer: &Vec<u8>) -> Result<Elf, Error> {
    let elf = Elf::parse(&buffer)?;

    // check for a 32-bit little-endian ARM binary
    if elf.is_64 || !elf.little_endian || elf.header.e_machine != goblin::elf::header::EM_ARM {
        return Err(Error::WrongElf());
    }

    Ok(elf)
}

fn create_emu(buffer: &Vec<u8>, elf: &Elf) -> Result<CpuARM, Error> {
    let emu = CpuARM::new(unicorn::Mode::THUMB)?;
    use unicorn::Protection;
    emu.mem_map(FLASH_BASE, FLASH_SIZE, Protection::READ | Protection::EXEC)?;
    emu.mem_map(SRAM_BASE, SRAM_SIZE, Protection::ALL)?;
    emu.mem_map(HARNESS_BASE, HARNESS_SIZE, Protection::ALL)?;

    // find any loadable program headers
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            let start = ph.p_offset as usize;
            let size = ph.p_filesz as usize;
            emu.mem_write(ph.p_paddr as u64, &buffer[start..][..size])?;
        }
    }

    // Reset the stack pointer from the word at FLASH_BASE
    let mut bytes = Cursor::new(emu.mem_read_as_vec(FLASH_BASE, 4)?);
    let sp = bytes.read_i32::<LittleEndian>()?;
    emu.reg_write_i32(RegisterARM::SP, sp)?;

    Ok(emu)
}

fn lookup_symbol(elf: &Elf, symbol: &str) -> Result<Sym, Error> {
    for sym in elf.syms.iter() {
        if sym.is_function() {
            if elf.strtab.get(sym.st_name).unwrap()? == symbol {
                return Ok(sym);
            }
        }
    }
    Err(Error::WrongElf())
}

fn run_test(test: &TestCase, buffer: &Vec<u8>, elf: &Elf) -> Result<(), Error> {
    let emu = create_emu(&buffer, &elf)?;

    // Set up registers
    for (reg, val) in &test.setup {
        emu.reg_write_i32(reg.reg, *val)?;
    }

    // Locate elf symbol
    let sym = lookup_symbol(&elf, &test.target)?;

    // Branch to the subroutine in question:
    // ldr      r12, [pc, #4]       0xdf 0xf8 0x04 0xc0
    // blx      r12                 0xe0 0x47
    // .align   4                   0x00 0x00
    // .word    sym.st_value        ...
    let mut call = vec![0xdf, 0xf8, 0x04, 0xc0, 0xe0, 0x47, 0x00, 0x00];
    call.write_u32::<LittleEndian>(sym.st_value as u32).unwrap();
    emu.mem_write(HARNESS_BASE, &call)?;

    emu.emu_start(HARNESS_BASE | 1, HARNESS_BASE + 6, 0, 0)?;

    for (reg, val) in &test.check {
        let rv = emu.reg_read_i32(reg.reg)?;
        if rv != *val {
            return Err(Error::TestMismatch(reg.reg, rv, *val));
        }
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: rustmtest <elf file> <test> [<test> ...]");
        std::process::exit(exitcode::USAGE);
    }

    let elf = &args[1];
    let path = Path::new(elf.as_str());
    let buffer = fs::read(path)?;
    let elf = load_elf(&buffer)?;

    let mut errcount = 0;
    for src in args.iter().skip(2) {
        let path = Path::new(src.as_str());
        let srcbuf = fs::read(path)?;
        let input = std::str::from_utf8(&srcbuf)?;
        let test = TestCase::parse(&input)?;
        match run_test(&test, &buffer, &elf) {
            Ok(()) => println!("{}... ok", test.name),
            Err(e) => {
                println!("{}... fail {}", test.name, e);
                errcount += 1;
            }
        }
    }

    if errcount > 0 {
        std::process::exit(errcount);
    }

    Ok(())
}
