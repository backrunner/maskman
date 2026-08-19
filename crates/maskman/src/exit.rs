use anyhow::Error;

pub fn code(error: &Error) -> i32 {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
    }) {
        return 4;
    }
    if error.chain().any(|cause| cause.downcast_ref::<maskman_config::ConfigError>().is_some()) {
        return 3;
    }
    if error.chain().any(|cause| cause.downcast_ref::<maskman_update::UpdateError>().is_some()) {
        return 7;
    }
    if error.chain().any(|cause| cause.downcast_ref::<maskman_platform::PlatformError>().is_some())
    {
        return 5;
    }
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("transport") || text.contains("protocol") || text.contains("network") {
        return 6;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::code;

    #[test]
    fn maps_stable_operational_exit_codes() {
        let permission =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert_eq!(code(&permission), 4);
        assert_eq!(
            code(&anyhow::Error::new(
                maskman_platform::PlatformError::ServiceManagementUnavailable
            )),
            5
        );
        assert_eq!(code(&anyhow::anyhow!("network transport failed")), 6);
        assert_eq!(
            code(&anyhow::Error::new(maskman_update::UpdateError::ReleaseKeyUnavailable)),
            7
        );
    }
}
