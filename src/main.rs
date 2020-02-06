extern crate exitcode;
extern crate unicorn;

use core::fmt;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use unicorn::{Cpu, CpuARM};

mod lex;

const FLASH_BASE: u64 = 0x08000000;
const FLASH_SIZE: usize = 0x00040000;
const SRAM_BASE: u64 = 0x20000000;
const SRAM_SIZE: usize = 0x00010000;

#[derive(Debug)]
enum Error {
    WrongElf(),
    Goblin(goblin::error::Error),
    Unicorn(unicorn::Error),
    IO(io::Error),
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

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::WrongElf() => write!(fmt, "Invalid ELF file: 32-bit little-endian ARM expected"),
            Error::Goblin(ref err) => write!(fmt, "{}", err),
            Error::Unicorn(ref err) => write!(fmt, "{}", err),
            Error::IO(ref err) => write!(fmt, "{}", err),
        }
    }
}

fn load_elf(buffer: &Vec<u8>) -> Result<CpuARM, Error> {
    let elf = goblin::elf::Elf::parse(&buffer)?;
    // check for a 32-bit little-endian ARM binary
    if elf.is_64 || !elf.little_endian || elf.header.e_machine != goblin::elf::header::EM_ARM {
        return Err(Error::WrongElf());
    }

    let emu = CpuARM::new(unicorn::Mode::THUMB)?;
    use unicorn::Protection;
    emu.mem_map(FLASH_BASE, FLASH_SIZE, Protection::READ | Protection::EXEC)?;
    emu.mem_map(SRAM_BASE, SRAM_SIZE, Protection::ALL)?;

    // find any loadable program headers
    for ph in elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            emu.mem_write(
                ph.p_paddr as u64,
                &buffer[ph.p_offset as usize..][..ph.p_filesz as usize],
            )?;
        }
    }

    Ok(emu)
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: rustmtest <elf file> <test> [<test> ...]");
        std::process::exit(exitcode::USAGE);
    }

    let elf = &args[1];

    let path = Path::new(elf.as_str());
    let buffer = fs::read(path)?;
    let emu = load_elf(&buffer)?;
    emu.emu_start(FLASH_BASE, FLASH_BASE + FLASH_SIZE as u64, 0, 1)?;
    println!("pc = {}", emu.reg_read_i32(unicorn::RegisterARM::PC)?);

    Ok(())
}
