use super::{
    audit_directory_ancestors, make_inheritable, spawn_worker, worker_identity, WORKER_GROUP,
    WORKER_USER,
};

#[test]
fn service_identity_is_fixed_and_not_user_supplied() {
    assert_eq!(worker_identity(), (WORKER_USER, WORKER_GROUP));
    assert!(WORKER_USER.chars().all(|value| value.is_ascii_alphanumeric()));
}

#[test]
fn worker_launch_requires_a_bounded_listener_set() {
    let result = spawn_worker(
        std::path::Path::new("/bin/false"),
        std::path::Path::new("/tmp/maskman.toml"),
        &[],
        None,
    );
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn inherited_socket_descriptor_can_be_explicitly_exported() {
    use std::{net::UdpSocket, os::fd::AsFd};

    let socket =
        UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("bind test socket: {error}"));
    make_inheritable(socket.as_fd())
        .unwrap_or_else(|error| panic!("mark test socket inheritable: {error}"));
    let flags = nix::fcntl::fcntl(socket.as_fd(), nix::fcntl::FcntlArg::F_GETFD)
        .unwrap_or_else(|error| panic!("read descriptor flags: {error}"));
    assert!(!nix::fcntl::FdFlag::from_bits_truncate(flags).contains(nix::fcntl::FdFlag::FD_CLOEXEC));
}

#[cfg(unix)]
#[test]
fn worker_access_rejects_non_searchable_ancestor() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "maskman-worker-access-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let nested = root.join("private");
    std::fs::create_dir_all(&nested)
        .unwrap_or_else(|error| panic!("create worker access test root: {error}"));
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|error| panic!("restrict worker access test root: {error}"));
    let result = audit_directory_ancestors(
        &nested,
        "worker test",
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
    );
    assert!(result.is_err());
    std::fs::remove_dir_all(&root)
        .unwrap_or_else(|error| panic!("remove worker access test root: {error}"));
}

#[cfg(unix)]
#[test]
fn worker_access_rejects_symlink_ancestor() {
    let root = std::env::temp_dir().join(format!(
        "maskman-worker-symlink-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let real = root.join("real");
    let link = root.join("link");
    std::fs::create_dir_all(&real)
        .unwrap_or_else(|error| panic!("create worker symlink test root: {error}"));
    std::os::unix::fs::symlink(&real, &link)
        .unwrap_or_else(|error| panic!("create worker symlink: {error}"));
    let result = audit_directory_ancestors(
        &link,
        "worker test",
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
    );
    assert!(result.is_err());
    std::fs::remove_dir_all(&root)
        .unwrap_or_else(|error| panic!("remove worker symlink test root: {error}"));
}
