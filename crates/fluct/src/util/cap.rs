use std::io;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drops all POSIX capabilities (effective, permitted, inheritable) for the current process.
pub fn drop_caps() -> io::Result<()> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let res = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut _ as *mut libc::c_void,
            data.as_ptr() as *const libc::c_void,
        )
    };

    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
