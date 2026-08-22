use std::{path::PathBuf, time::Duration};

pub(super) struct PlatformService {
    spec: maskman_platform::ServiceSpec,
    control_socket: PathBuf,
    expected_version: String,
}

impl PlatformService {
    pub(super) fn new(
        spec: maskman_platform::ServiceSpec,
        config: &maskman_config::CompiledConfig,
        expected_version: String,
    ) -> Self {
        Self {
            spec,
            control_socket: maskman_server::control::socket_path(config),
            expected_version,
        }
    }
}

impl maskman_update::ServiceController for PlatformService {
    fn stop(&self) -> Result<(), maskman_update::UpdateError> {
        maskman_platform::service_control(&self.spec, maskman_platform::ServiceAction::Stop)
            .map_err(|error| maskman_update::UpdateError::Health(error.to_string()))
    }

    fn start(&self) -> Result<(), maskman_update::UpdateError> {
        maskman_platform::service_control(&self.spec, maskman_platform::ServiceAction::Start)
            .map_err(|error| maskman_update::UpdateError::Health(error.to_string()))
    }

    fn healthy(&self) -> Result<bool, maskman_update::UpdateError> {
        let running = maskman_platform::service_status(&self.spec)
            .map_err(|error| maskman_update::UpdateError::Health(error.to_string()))?
            .running;
        if !running {
            return Ok(false);
        }
        let response = match maskman_server::control::request_blocking(
            &self.control_socket,
            maskman_server::control::ControlCommand::Status,
            Duration::from_millis(500),
        ) {
            Ok(response) => response,
            Err(maskman_server::control::ControlError::Io(_)) => return Ok(false),
            Err(error) => return Err(maskman_update::UpdateError::Health(error.to_string())),
        };
        daemon_is_ready(response, &self.expected_version)
    }
}

fn daemon_is_ready(
    response: maskman_server::control::ControlResponse,
    expected_version: &str,
) -> Result<bool, maskman_update::UpdateError> {
    if !response.ok {
        return Err(maskman_update::UpdateError::Health(
            response.error.unwrap_or_else(|| "daemon rejected status request".into()),
        ));
    }
    let status = response
        .status
        .ok_or_else(|| maskman_update::UpdateError::Health("daemon returned no status".into()))?;
    if status.version != expected_version {
        return Err(maskman_update::UpdateError::Health(format!(
            "daemon version {} does not match installed version {expected_version}",
            status.version
        )));
    }
    Ok(status.ready)
}

#[cfg(test)]
mod tests {
    use maskman_server::{control::ControlResponse, RuntimeSnapshot};

    use super::daemon_is_ready;

    #[test]
    fn readiness_requires_ready_status_and_exact_release_version() {
        assert!(daemon_is_ready(response("1.2.3", true), "1.2.3").unwrap_or(false));
        assert!(!daemon_is_ready(response("1.2.3", false), "1.2.3").unwrap_or(true));
        assert!(daemon_is_ready(response("1.2.2", true), "1.2.3").is_err());
    }

    fn response(version: &str, ready: bool) -> ControlResponse {
        ControlResponse {
            version: 1,
            request_id: 1,
            ok: true,
            status: Some(maskman_server::control::DaemonStatus {
                version: version.into(),
                pid: 1,
                ready,
                config_generation: 1,
                config_hash_sha256: None,
                listen: Vec::new(),
                metrics_listen: "127.0.0.1:9090".into(),
                runtime: RuntimeSnapshot {
                    uptime_seconds: 0,
                    active_connections: 0,
                    accepted_connections: 0,
                    active_udp_sessions: 0,
                    active_ip_sessions: 0,
                    forwarded_packets: 0,
                    dropped_packets: 0,
                    last_error: None,
                },
            }),
            error: None,
        }
    }
}
