use std::{
    path::PathBuf,
    process::{Child, ExitStatus},
    time::{Duration, Instant},
};

use maskman_config::CompiledConfig;

use crate::{resources, ServerError};

/// Root service entry point. All platform-owned resources are opened before
/// the worker is spawned, and the journal is cleaned only after the worker has
/// exited so a crashed worker cannot leave an untracked route or TUN behind.
pub async fn run(config: CompiledConfig, config_path: PathBuf) -> Result<(), ServerError> {
    if config.listen.is_empty() {
        return Err(ServerError::MissingListener);
    }
    if maskman_platform::current_uid() != 0 {
        return Err(ServerError::Transport(
            "supervisor role requires root; run `maskman serve` directly for development".into(),
        ));
    }
    if !maskman_platform::worker_identity_available() {
        return Err(ServerError::Transport(format!(
            "dedicated worker identity {} is not present",
            maskman_platform::worker_identity().0
        )));
    }
    crate::validate_tls(&config).map_err(|error| ServerError::Transport(error.to_string()))?;

    let resources = resources::prepare(&config).await?;
    let listener_fds = match resources.listener_fds() {
        Ok(fds) => fds,
        Err(error) => {
            let cleanup = resources::cleanup(resources.journal_path()).await;
            drop(resources);
            return combine_startup_error(error, cleanup);
        }
    };
    let tun_fd = match resources.tun_fd() {
        Ok(fd) => fd,
        Err(error) => {
            let cleanup = resources::cleanup(resources.journal_path()).await;
            drop(resources);
            return combine_startup_error(error, cleanup);
        }
    };
    let binary = match std::env::current_exe() {
        Ok(binary) => binary,
        Err(error) => {
            let cleanup = resources::cleanup(resources.journal_path()).await;
            drop(resources);
            return combine_startup_error(
                ServerError::Transport(format!("locate worker binary: {error}")),
                cleanup,
            );
        }
    };
    let child = match maskman_platform::spawn_worker(&binary, &config_path, &listener_fds, tun_fd) {
        Ok(child) => child,
        Err(error) => {
            let cleanup = resources::cleanup(resources.journal_path()).await;
            drop(resources);
            return combine_startup_error(
                ServerError::Transport(format!("spawn worker: {error}")),
                cleanup,
            );
        }
    };

    let status = match wait_for_worker(child).await {
        Ok(status) => status,
        Err(error) => {
            let cleanup = resources::cleanup(resources.journal_path()).await;
            drop(resources);
            return combine_startup_error(error, cleanup);
        }
    };
    let cleanup = resources::cleanup(resources.journal_path()).await;
    drop(resources);
    cleanup?;
    if status.success() {
        Ok(())
    } else {
        Err(ServerError::Task(format!("worker exited with status {status}")))
    }
}

async fn wait_for_worker(mut child: Child) -> Result<ExitStatus, ServerError> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| ServerError::Signal(error.to_string()))?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|error| ServerError::Signal(error.to_string()))?;
    let mut stopping = false;
    let mut stopping_since: Option<Instant> = None;
    loop {
        if let Some(status) =
            child.try_wait().map_err(|error| ServerError::Task(error.to_string()))?
        {
            return Ok(status);
        }
        if stopping_since.is_some_and(|started| started.elapsed() > Duration::from_secs(5)) {
            child.kill().map_err(|error| ServerError::Task(format!("kill worker: {error}")))?;
            stopping_since = None;
        }
        #[cfg(unix)]
        {
            tokio::select! {
                _ = terminate.recv(), if !stopping => {
                    stopping = true;
                    stopping_since = Some(Instant::now());
                    let _ = maskman_platform::terminate_worker(&child);
                }
                _ = interrupt.recv(), if !stopping => {
                    stopping = true;
                    stopping_since = Some(Instant::now());
                    let _ = maskman_platform::terminate_worker(&child);
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

fn combine_startup_error(
    primary: ServerError,
    cleanup: Result<(), ServerError>,
) -> Result<(), ServerError> {
    match cleanup {
        Ok(()) => Err(primary),
        Err(error) => Err(ServerError::Transport(format!("{primary}; {error}"))),
    }
}
