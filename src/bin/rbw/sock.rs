use std::io::{BufRead as _, Write as _};

use anyhow::Context as _;

#[cfg(unix)]
pub struct Sock(std::os::unix::net::UnixStream);
#[cfg(windows)]
pub struct Sock(std::fs::File);

impl Sock {
    // not returning anyhow::Result here because we want to be able to handle
    // specific kinds of std::io::Results differently
    #[cfg(unix)]
    pub fn connect() -> std::io::Result<Self> {
        Ok(Self(std::os::unix::net::UnixStream::connect(
            rbw::dirs::socket_file(),
        )?))
    }

    #[cfg(windows)]
    pub fn connect() -> std::io::Result<Self> {
        use std::os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _};
        const ERROR_PIPE_BUSY: i32 = 231;
        const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
        let mut tries = 0;
        loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                // don't let the pipe server impersonate us
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(rbw::dirs::socket_file())
            {
                Ok(f) => {
                    rbw::win::check_pipe_owner(f.as_raw_handle())?;
                    return Ok(Self(f));
                }
                // all pipe instances momentarily in use: retry for ~1s
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && tries < 100 =>
                {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn send(
        &mut self,
        msg: &rbw::protocol::Request,
    ) -> anyhow::Result<()> {
        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(msg)
                .context("failed to serialize message to agent")?
                .as_bytes(),
        )
        .context("failed to send message to agent")?;
        sock.write_all(b"\n")
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> anyhow::Result<rbw::protocol::Response> {
        let Self(sock) = self;
        let mut buf = std::io::BufReader::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .context("failed to read message from agent")?;
        serde_json::from_str(&line)
            .context("failed to parse message from agent")
    }
}
