use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;

// windows has no fork(): the parent respawns itself detached with
// --no-daemonize and waits for the pipe to appear, so no ack is needed
#[cfg(windows)]
pub struct StartupAck;

#[cfg(windows)]
impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    use std::os::windows::{ffi::OsStrExt as _, fs::OpenOptionsExt as _};
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, WaitForSingleObject,
        CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, PROCESS_INFORMATION,
        STARTUPINFOW,
    };
    const FILE_SHARE_READ: u32 = 1;
    const ERROR_SHARING_VIOLATION: i32 = 32;

    if no_daemonize {
        redirect_std_handles_if_detached()?;
        // an exclusive (read-shared) open stands in for flock: a second
        // agent gets a sharing violation
        let mut pidfile = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ)
            .open(rbw::dirs::pid_file())
        {
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
                // already running, same exit code as the unix path
                std::process::exit(23);
            }
            res => res.context("failed to open pid file")?,
        };
        pidfile.set_len(0).context("failed to write pid file")?;
        writeln!(pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // keep the pidfile open (and locked) until the process exits
        std::mem::forget(pidfile);
        return Ok(None);
    }

    // spawn with bInheritHandles=FALSE: std::process::Command always inherits
    // every inheritable handle, which leaks the caller's stdout pipe into the
    // long-lived agent and makes e.g. `$x = rbw lock` hang forever
    let exe = std::env::current_exe()?;
    let app: Vec<u16> =
        exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut cmdline: Vec<u16> = std::ffi::OsString::from(format!(
        "\"{}\" --no-daemonize",
        exe.display()
    ))
    .encode_wide()
    .chain(std::iter::once(0))
    .collect();
    // safety: zeroed STARTUPINFOW/PROCESS_INFORMATION are valid inputs;
    // buffers are nul-terminated and outlive the call
    let pi = unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>().try_into().unwrap();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        ) == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to spawn agent");
        }
        CloseHandle(pi.hThread);
        pi
    };
    let pipe = rbw::dirs::socket_file();
    for _ in 0..500 {
        // safety: valid process handle owned by us
        unsafe {
            if WaitForSingleObject(pi.hProcess, 10) == WAIT_OBJECT_0 {
                let mut code = 1;
                GetExitCodeProcess(pi.hProcess, &mut code);
                std::process::exit(code.cast_signed());
            }
        }
        if rbw::win::pipe_exists(&pipe) {
            std::process::exit(0);
        }
    }
    anyhow::bail!("timed out waiting for the agent to start")
}

// the detached agent starts without std handles; send its output to the
// same log files the unix daemon uses
#[cfg(windows)]
fn redirect_std_handles_if_detached() -> anyhow::Result<()> {
    use std::os::windows::io::IntoRawHandle as _;
    use windows_sys::Win32::System::Console::{
        GetStdHandle, SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };
    // safety: plain win32 calls; the file handles are leaked on purpose
    unsafe {
        if !GetStdHandle(STD_ERROR_HANDLE).is_null() {
            return Ok(());
        }
        for (std_h, path) in [
            (STD_OUTPUT_HANDLE, rbw::dirs::agent_stdout_file()),
            (STD_ERROR_HANDLE, rbw::dirs::agent_stderr_file()),
        ] {
            let f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)?;
            SetStdHandle(std_h, f.into_raw_handle());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub struct StartupAck {
    writer: std::os::unix::io::OwnedFd,
}

#[cfg(unix)]
impl StartupAck {
    pub fn ack(self) -> anyhow::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

#[cfg(unix)]
pub fn daemonize(no_daemonize: bool) -> anyhow::Result<Option<StartupAck>> {
    if no_daemonize {
        let mut pidfile = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o666)
            .open(rbw::dirs::pid_file())
            .context("failed to open pid file")?;
        rustix::fs::flock(
            &pidfile,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .context("failed to lock pid file")?;
        writeln!(pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);

        return Ok(None);
    }

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(rbw::dirs::agent_stderr_file())?;

    let (r, w) = rustix::pipe::pipe()?;
    let daemonize = daemonize::Daemonize::new()
        .pid_file(rbw::dirs::pid_file())
        .stdout(stdout)
        .stderr(stderr);
    let res = match daemonize.execute() {
        daemonize::Outcome::Parent(_) => {
            drop(w);
            let mut buf = [0; 1];
            // unwraps are necessary because not really a good way to handle
            // errors here otherwise
            rustix::io::read(&r, &mut buf).unwrap();
            drop(r);
            std::process::exit(0);
        }
        daemonize::Outcome::Child(res) => res,
    };

    drop(r);

    match res {
        Ok(_) => (),
        Err(e) => {
            // XXX super gross, but daemonize removed the ability to match
            // on specific error types for some reason?
            if e.to_string().contains("unable to lock pid file") {
                // this means that there is already an agent running, so
                // return a special exit code to allow the cli to detect
                // this case and not error out
                std::process::exit(23);
            } else {
                panic!("failed to daemonize: {e}");
            }
        }
    }

    Ok(Some(StartupAck { writer: w }))
}
