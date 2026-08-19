use crate::UpdateError;

pub fn target_triple() -> Result<&'static str, UpdateError> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok("x86_64-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Ok("aarch64-unknown-linux-musl")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("aarch64-apple-darwin")
    } else {
        Err(UpdateError::UnsupportedTarget)
    }
}
