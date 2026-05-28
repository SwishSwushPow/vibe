//! Apple's VZNATNetworkDeviceAttachment sometimes drops packets and gets wrecked for any running VMs if host networking changes (e.g., you enable/disable a VPN).
//! See: https://github.com/lynaghk/vibe/issues/27
//!
//! So Vibe embeds https://github.com/nirs/vmnet-helper which enables more reliable NAT and also bridged networking.
//! We use a fork that accepts a "liveness" pipe from Vibe, so that it reliably exits whenever Vibe drops the other end.
//! This works even if Vibe is SIGKILL'd, since the kernel handles closing the pipe.

//! On MacOS 15 and earlier, vmnet-helper must be run by root from a location owned by root.
//! Since running vibe under sudo is risky (and annoying!), we instead prompt folks on MacOS 15 with commands to update their sudoers file so that vmnet-helper can be run without a password.

use std::{
    fs,
    io::{self, BufRead, BufReader},
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::{fs::PermissionsExt, net::UnixDatagram, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
};

const VMNET_HELPER: &[u8] = include_bytes!(env!("BUNDLED_VMNET_HELPER_PATH"));
const VMNET_HELPER_INSTALL_PATH: &str = "/opt/vibe/vmnet-helper";
const VMNET_HELPER_SUDOERS_PATH: &str = "/etc/sudoers.d/vibe-vmnet-helper";

const VMNET_HELPER_FD: RawFd = 3;
const VMNET_PARENT_LIVENESS_FD: RawFd = 4;
const VMNET_SENDBUF_BYTES: libc::c_int = 1024 * 1024;
const VMNET_RECVBUF_BYTES: libc::c_int = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkMode {
    VzNat,
    VmnetNat,
    VmnetBridged { shared_interface: String },
}

pub enum PreparedNetworkBackend {
    VzNat,
    VmnetHelper {
        vm_socket_fd: Option<OwnedFd>,
        _liveness: OwnedFd,
        _helper: VmnetHelperProcess,
    },
}

impl NetworkMode {
    pub fn parse(value: &str) -> Self {
        match value {
            "nat" => Self::VmnetNat,
            "vznat" => Self::VzNat,
            shared_interface => Self::VmnetBridged {
                shared_interface: shared_interface.to_string(),
            },
        }
    }

    pub fn prepare(
        &self,
        vmnet_helper_path: &Path,
    ) -> Result<PreparedNetworkBackend, Box<dyn std::error::Error>> {
        match self {
            NetworkMode::VzNat => Ok(PreparedNetworkBackend::VzNat),
            NetworkMode::VmnetNat | NetworkMode::VmnetBridged { .. } => {
                ensure_vmnet_helper_extracted(vmnet_helper_path);

                let macos_major: u32 = String::from_utf8(
                    Command::new("sw_vers")
                        .arg("-productVersion")
                        .output()
                        .expect("failed to run sw_vers -productVersion")
                        .stdout,
                )
                .expect("sw_vers -productVersion returned invalid UTF-8")
                .trim()
                .split('.')
                .next()
                .expect("sw_vers -productVersion returned an empty version")
                .parse()
                .expect("failed to parse macOS major version from sw_vers");

                let vmnet_helper_exec_path = if macos_major >= 26 {
                    vmnet_helper_path.to_str().unwrap()
                } else {
                    ensure_privileged_vmnet_helper_installed(vmnet_helper_path);
                    VMNET_HELPER_INSTALL_PATH
                };

                if let NetworkMode::VmnetBridged { shared_interface } = self {
                    let output = Command::new(vmnet_helper_path)
                        .arg("--list-shared-interfaces")
                        .output()?;

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let available_interfaces: Vec<&str> =
                        stdout.lines().filter(|l| !l.is_empty()).collect();

                    if !available_interfaces.contains(&shared_interface.as_str()) {
                        eprintln!(
                            "Shared interface '{}' is not available. Available interfaces:\n{}",
                            shared_interface,
                            available_interfaces.join("\n"),
                        );
                        std::process::exit(1);
                    }
                }

                let mut command = {
                    if macos_major >= 26 {
                        Command::new(vmnet_helper_exec_path)
                    } else {
                        let mut cmd = Command::new("sudo");
                        cmd.args(["--non-interactive", "--close-from=5"]);
                        cmd.arg(vmnet_helper_exec_path);
                        cmd
                    }
                };

                command.arg("--fd");
                command.arg(VMNET_HELPER_FD.to_string());

                command.arg("--parent-liveness-fd");
                command.arg(VMNET_PARENT_LIVENESS_FD.to_string());

                match self {
                    NetworkMode::VmnetNat => {
                        command.arg("--operation-mode");
                        command.arg("shared");
                    }
                    NetworkMode::VmnetBridged { shared_interface } => {
                        command.arg("--operation-mode");
                        command.arg("bridged");
                        command.arg("--shared-interface");
                        command.arg(shared_interface.clone());
                    }
                    NetworkMode::VzNat => unreachable!("vznat does not use vmnet-helper"),
                }

                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    // TODO: log via https://github.com/steven-joruk/oslog ?
                    .stderr(Stdio::null());

                let (vm_socket_fd, helper_socket_fd) = create_datagram_pair();
                let helper_raw_fd = helper_socket_fd.as_raw_fd();

                let (helper_liveness_read_fd, helper_liveness_write_fd) = crate::create_pipe();
                let helper_liveness_raw_fd = helper_liveness_read_fd.as_raw_fd();

                // Assign child file descriptors to the ones vmnet-helper expects.
                unsafe {
                    command.pre_exec(move || {
                        let fds = [
                            (helper_raw_fd, VMNET_HELPER_FD),
                            (helper_liveness_raw_fd, VMNET_PARENT_LIVENESS_FD),
                        ];

                        for (src_fd, dst_fd) in fds {
                            if libc::dup2(src_fd, dst_fd) == -1 {
                                return Err(io::Error::last_os_error());
                            }
                            if src_fd != dst_fd {
                                libc::close(src_fd);
                            }
                        }
                        Ok(())
                    });
                }

                let mut helper = VmnetHelperProcess {
                    child: command.spawn()?,
                };
                helper.wait_until_ready()?;

                Ok(PreparedNetworkBackend::VmnetHelper {
                    vm_socket_fd: Some(vm_socket_fd),
                    _liveness: helper_liveness_write_fd,
                    _helper: helper,
                })
            }
        }
    }
}

fn configure_vmnet_socket(fd: RawFd) {
    for (name, opt, value) in [
        ("SO_SNDBUF", libc::SO_SNDBUF, VMNET_SENDBUF_BYTES),
        ("SO_RCVBUF", libc::SO_RCVBUF, VMNET_RECVBUF_BYTES),
    ] {
        let status = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if status != 0 {
            eprintln!(
                "Warning: failed to set {name} on vmnet socket: {}",
                io::Error::last_os_error()
            );
        }
    }
}

fn create_datagram_pair() -> (OwnedFd, OwnedFd) {
    let (left, right) = UnixDatagram::pair().expect("Failed to create datagram pair");
    configure_vmnet_socket(left.as_raw_fd());
    configure_vmnet_socket(right.as_raw_fd());
    (left.into(), right.into())
}

fn ensure_vmnet_helper_extracted(path: &Path) {
    if fs::read(path).ok().as_deref() == Some(VMNET_HELPER) {
        return;
    }
    let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp_path, VMNET_HELPER).unwrap();
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::rename(&temp_path, path).unwrap();
}

fn ensure_privileged_vmnet_helper_installed(helper_source_path: &Path) {
    let helper_is_current = fs::read(VMNET_HELPER_INSTALL_PATH)
        .map(|bytes| bytes == VMNET_HELPER)
        .unwrap_or(false);

    let sudoers_exists = Path::new(VMNET_HELPER_SUDOERS_PATH).exists();

    if !(helper_is_current && sudoers_exists) {
        println!(
            "On MacOS < 26, vmnet-helper must be run as root to provide networking.
Please enable this by running the following:

sudo install -d -m 0755 {parent}
sudo install -o root -g wheel -m 0755 {source} {VMNET_HELPER_INSTALL_PATH}
cat <<'EOF' | sudo tee {VMNET_HELPER_SUDOERS_PATH} >/dev/null
  %staff  ALL = (root) NOPASSWD: {VMNET_HELPER_INSTALL_PATH}
  Defaults:%staff closefrom_override
EOF
sudo chmod 0440 {VMNET_HELPER_SUDOERS_PATH}
",
            parent = Path::new(VMNET_HELPER_INSTALL_PATH)
                .parent()
                .unwrap()
                .display(),
            source = helper_source_path.display(),
        );
        std::process::exit(1);
    }
}

pub struct VmnetHelperProcess {
    child: Child,
}

impl VmnetHelperProcess {
    fn wait_until_ready(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let stdout = self
            .child
            .stdout
            .take()
            .ok_or("vmnet-helper stdout was not captured")?;
        let mut reader = BufReader::new(stdout);
        let mut pollfd = libc::pollfd {
            fd: reader.get_ref().as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };

        let timeout_ms = 3000;
        let poll_result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if poll_result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if poll_result == 0 {
            return Err("Timed out waiting for vmnet-helper to become ready.".into());
        }

        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            let status = self.child.wait()?;

            return Err(format!(
                "vmnet-helper exited before becoming ready ({}).",
                match status.code() {
                    Some(code) => format!("exit code {code}"),
                    None => "terminated by signal".to_string(),
                },
            )
            .into());
        }

        // Don't care about output from vmnet-helper once we've gotten one line.
        drop(reader);

        Ok(())
    }
}
