use anyhow::Context as _;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;
#[cfg(unix)]
pub type Listener = tokio::net::UnixListener;
#[cfg(windows)]
pub type Stream = tokio::net::windows::named_pipe::NamedPipeServer;

pub struct Sock(Stream);

impl Sock {
    pub fn new(s: Stream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &rbw::protocol::Response,
    ) -> anyhow::Result<()> {
        if let rbw::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> anyhow::Result<std::result::Result<rbw::protocol::Request, String>>
    {
        let Self(sock) = self;
        let mut buf = tokio::io::BufStream::new(sock);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        Ok(serde_json::from_str(&line)
            .map_err(|e| format!("failed to parse message '{line}': {e}")))
    }
}

#[cfg(unix)]
pub fn incoming(
    listener: Listener,
) -> tokio_stream::wrappers::UnixListenerStream {
    tokio_stream::wrappers::UnixListenerStream::new(listener)
}

#[cfg(windows)]
pub struct Listener {
    server: Stream,
    name: std::path::PathBuf,
    // leaked security descriptor, shared by every pipe instance
    sd: usize,
}

#[cfg(windows)]
fn create_pipe(
    name: &std::path::Path,
    sd: usize,
    first: bool,
) -> std::io::Result<Stream> {
    let mut sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<
            windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
        >()
        .try_into()
        .unwrap(),
        lpSecurityDescriptor: sd as *mut core::ffi::c_void,
        bInheritHandle: 0,
    };
    // safety: sa and the descriptor it points to are valid for the call
    unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&raw mut sa).cast(),
            )
    }
}

#[cfg(windows)]
pub fn listen() -> anyhow::Result<Listener> {
    let name = rbw::dirs::socket_file();
    let sd = rbw::win::pipe_security_descriptor()
        .context("failed to build pipe security descriptor")?
        as usize;
    // first_pipe_instance fails if anyone (e.g. another user) already
    // created a pipe with this name
    let server =
        create_pipe(&name, sd, true).context("failed to listen on pipe")?;
    log::debug!("listening on pipe {}", name.to_string_lossy());
    Ok(Listener { server, name, sd })
}

/// Yields one connected pipe instance per client, creating a fresh
/// instance for the next client each time.
#[cfg(windows)]
pub fn incoming(
    listener: Listener,
) -> impl futures_util::Stream<Item = std::io::Result<Stream>> {
    futures_util::stream::unfold(Some(listener), |l| async move {
        let mut l = l?;
        let res = l.server.connect().await;
        match create_pipe(&l.name, l.sd, false) {
            Ok(next) => {
                let cur = std::mem::replace(&mut l.server, next);
                Some((res.map(|()| cur), Some(l)))
            }
            Err(e) => Some((Err(e), None)),
        }
    })
}

#[cfg(unix)]
pub fn listen() -> anyhow::Result<tokio::net::UnixListener> {
    let path = rbw::dirs::socket_file();
    // if the socket already doesn't exist, that's fine
    let _ = std::fs::remove_file(&path);
    let sock = tokio::net::UnixListener::bind(&path)
        .context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}
