// Windows-only helpers: the agent listens on a named pipe instead of a unix
// socket, and the pipe must only be usable by the current user.

use std::os::windows::ffi::OsStrExt as _;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject,
    INFINITE, PROCESS_SYNCHRONIZE,
};

const SDDL_REVISION_1: u32 = 1;

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide_ptr(p: *const u16) -> String {
    // safety: p is a nul-terminated string returned by the OS
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// `TOKEN_USER` of the current process; the SID lives inside the buffer.
struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    fn current() -> std::io::Result<Self> {
        // safety: plain win32 calls with correctly sized buffers
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let mut buf = vec![0_u64; 64]; // 512 bytes, u64 for alignment
            let mut len = 0;
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                512,
                &mut len,
            );
            let err = std::io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            Ok(Self(buf))
        }
    }

    fn sid(&self) -> *mut core::ffi::c_void {
        // safety: buffer was filled by GetTokenInformation(TokenUser)
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

pub fn current_user_sid_string() -> std::io::Result<String> {
    let user = TokenUserBuf::current()?;
    let mut s: *mut u16 = std::ptr::null_mut();
    // safety: valid sid, out pointer freed with LocalFree
    unsafe {
        if ConvertSidToStringSidW(user.sid(), &mut s) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ret = from_wide_ptr(s);
        LocalFree(s.cast());
        Ok(ret)
    }
}

/// SDDL for the agent pipe: owned by the current user, protected DACL with a
/// single ACE granting GENERIC_ALL to the current user only.
pub fn pipe_sddl() -> std::io::Result<String> {
    let sid = current_user_sid_string()?;
    Ok(format!("O:{sid}D:P(A;;GA;;;{sid})"))
}

/// Returns a security descriptor for the pipe. It is intentionally leaked:
/// it is needed for every pipe instance for the lifetime of the agent.
pub fn pipe_security_descriptor() -> std::io::Result<*mut core::ffi::c_void> {
    let sddl = wide(std::ffi::OsStr::new(&pipe_sddl()?));
    let mut sd = std::ptr::null_mut();
    // safety: valid nul-terminated wide string and out pointer
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(sd)
}

/// Refuse to talk to a pipe that is not owned by the current user (guards
/// against another user squatting the pipe name before the agent starts).
pub fn check_pipe_owner(
    handle: std::os::windows::io::RawHandle,
) -> std::io::Result<()> {
    let user = TokenUserBuf::current()?;
    let mut owner = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    // safety: valid handle; sd freed with LocalFree, owner points into sd
    unsafe {
        let err = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        if err != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(err.cast_signed()));
        }
        let same = EqualSid(owner, user.sid()) != 0;
        LocalFree(sd);
        if same {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "agent pipe is not owned by the current user",
            ))
        }
    }
}

/// True once a server instance of the named pipe exists.
pub fn pipe_exists(name: &std::path::Path) -> bool {
    let name = wide(name.as_os_str());
    // WaitNamedPipeW fails immediately with ERROR_FILE_NOT_FOUND if the pipe
    // does not exist, and does not consume a server instance
    unsafe {
        windows_sys::Win32::System::Pipes::WaitNamedPipeW(name.as_ptr(), 1)
            != 0
    }
}

pub fn wait_for_exit(pid: u32) {
    // safety: plain win32 calls; a null handle means the process is gone
    unsafe {
        let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if !h.is_null() {
            WaitForSingleObject(h, INFINITE);
            CloseHandle(h);
        }
    }
}
