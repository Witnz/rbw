use crate::prelude::*;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&cache_dir(), 0o700)?;
    create_dir_all_with_permissions(&runtime_dir(), 0o700)?;
    create_dir_all_with_permissions(&data_dir(), 0o700)?;

    Ok(())
}

// on windows the per-user profile dirs are already private to the user
#[cfg(windows)]
fn create_dir_all_with_permissions(
    path: &std::path::Path,
    _mode: u32,
) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::CreateDirectory {
        source,
        file: path.to_path_buf(),
    })
}

#[cfg(unix)]
fn create_dir_all_with_permissions(
    path: &std::path::Path,
    mode: u32,
) -> Result<()> {
    // ensure the initial directory creation happens with the correct mode,
    // to avoid race conditions
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // but also make sure to forcibly set the mode, in case the directory
    // already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

const INVALID_PATH: &percent_encoding::AsciiSet =
    &percent_encoding::CONTROLS.add(b'/').add(b'%').add(b':');
// windows forbids more characters in file names, and ':' would create an
// NTFS alternate data stream, so encode both parts and join with ';'
#[cfg(windows)]
const INVALID_PATH_WIN: &percent_encoding::AsciiSet = &INVALID_PATH
    .add(b'\\')
    .add(b'*')
    .add(b'?')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'|')
    .add(b';');
pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let enc = |s: &str| {
            percent_encoding::utf8_percent_encode(s, INVALID_PATH_WIN)
                .to_string()
        };
        cache_dir().join(format!("{};{}.json", enc(server), enc(email)))
    }
    #[cfg(unix)]
    {
        let server =
            percent_encoding::percent_encode(server.as_bytes(), INVALID_PATH)
                .to_string();
        cache_dir().join(format!("{server}:{email}.json"))
    }
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

#[cfg(unix)]
pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

// on windows the agent listens on a named pipe; its ACL (see win.rs), not the
// name, is what keeps other users out
#[cfg(windows)]
pub fn socket_file() -> std::path::PathBuf {
    let user = std::env::var("USERNAME").unwrap_or_default();
    format!(r"\\.\pipe\{}-{user}-agent", profile()).into()
}

pub fn ssh_agent_socket_file() -> std::path::PathBuf {
    runtime_dir().join("ssh-agent-socket")
}

fn config_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.config_dir().to_path_buf()
}

fn cache_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.cache_dir().to_path_buf()
}

fn data_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.data_dir().to_path_buf()
}

#[cfg(windows)]
fn runtime_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.data_local_dir().join("runtime")
}

#[cfg(unix)]
fn runtime_dir() -> std::path::PathBuf {
    let project_dirs =
        directories::ProjectDirs::from("", "", &profile()).unwrap();
    project_dirs.runtime_dir().map_or_else(
        || {
            format!(
                "{}/{}-{}",
                std::env::temp_dir().to_string_lossy(),
                &profile(),
                rustix::process::getuid().as_raw()
            )
            .into()
        },
        std::path::Path::to_path_buf,
    )
}

pub fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(profile) if !profile.is_empty() => format!("rbw-{profile}"),
        _ => "rbw".to_string(),
    }
}
