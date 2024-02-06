use windows::{
    Win32::System::Memory::*,
    Win32::System::Threading::*,
    Win32::Foundation::*,
    Win32::System::Diagnostics::Debug::*
};

use md5;
use std::fs;
use std::env;
use std::ffi::c_void;



struct Buffer {
    addr: u64,
    sz: usize,
}

impl Buffer {
    pub fn new(addr:u64, sz:usize) -> Buffer {
        Buffer {
            addr: addr,
            sz: sz,
        }
    }
}

fn scan(hndl:HANDLE) -> Vec<Buffer> {
    let mut buffers:Vec<Buffer> = Vec::new();


    let mut addr:u64 = 0;
    loop {
        unsafe {

            let mut mbi:MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            let r = VirtualQueryEx(hndl, Some(addr as *const c_void), 
                &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>());

            if r > 0 {
                let buff = Buffer::new(addr, mbi.RegionSize);
                buffers.push(buff);
                addr += mbi.RegionSize as u64;
            } else {
                addr += 1;
            }

            if addr >= 0x7fffffff {
                break;
            }
        }
    }


    buffers
}

fn memdump(hndl:HANDLE, buff:Buffer, id:usize) {
    unsafe {
        let mut mem:Vec<u8> = vec![0; buff.sz];
        let bytes_read:Option<*mut usize> = None;
        if let Ok(_) = ReadProcessMemory(hndl, buff.addr as *const c_void, 
            mem.as_mut_ptr() as *mut c_void, buff.sz, bytes_read) {
  
            /*let read = match bytes_read {
                Some(x) => x as usize,
                None => 0,
            };*/

            let hash = md5::compute(&mem);

            println!("{:x} 0x{:x} sz:{}", id, buff.addr, buff.sz);
            let filename = format!("{:x}_{:x}_{}.bin", hash, buff.addr, buff.sz);
            fs::write(filename, mem).expect("error saving memdump");

        } else {
            println!("cannot dump {} 0x{:x} {}", id, buff.addr, buff.sz);
        }

    }
}

fn main() {
    let args:Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("provide a pid");
        return;
    }

    let pid = args[1].parse::<u32>().expect("provide a valid pid");

    unsafe {
        let hndl = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .expect("cannot open pid");

        if hndl.is_invalid() {
            println!("cannot open pid");
            return;
        }


        let mut id:usize = 0;
        loop {
            let buffers = scan(hndl);

            println!("Buffers found:");
            id += 1;
            for buff in buffers {
                memdump(hndl, buff, id);
            }
        }

    };
}
