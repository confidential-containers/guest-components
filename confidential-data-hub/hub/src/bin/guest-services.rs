mod message;
mod ttrpc_server;

use std::sync::Arc;
use std::{collections::HashMap, os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, instrument, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use ttrpc::asynchronous::Service;
use ttrpc::r#async::Server as TtrpcServer;

use confidential_data_hub::CdhConfig;
use protos::ttrpc::cdh::api_ttrpc;
use ttrpc_server::Server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    /// Run image pull service
    ImagePull {
        /// Socket path for the service
        #[arg(short, long, default_value = "/run/guest-services/imagepull.sock")]
        socket: PathBuf,
        /// Configuration directory
        #[arg(short, long, default_value = "/run/measured-cfg")]
        config_dir: PathBuf,
    },
    /// Run sealed secrets service
    SealedSecrets {
        #[arg(
            short,
            long,
            default_value = "/run/guest-services/sealedsecrets.sock"
        )]
        socket: PathBuf,
        #[arg(short, long, default_value = "/run/measured-cfg")]
        config_dir: PathBuf,
    },
    /// Run secure mount service
    SecureMount {
        #[arg(short, long, default_value = "/run/guest-services/securemount.sock")]
        socket: PathBuf,
        #[arg(short, long, default_value = "/run/measured-cfg")]
        config_dir: PathBuf,
    },
    /// Run get resource service
    GetResource {
        #[arg(short, long, default_value = "/run/guest-services/getresource.sock")]
        socket: PathBuf,
        #[arg(short, long, default_value = "/run/measured-cfg")]
        config_dir: PathBuf,
    },
}

#[instrument(skip(service), fields(socket = %socket_path.display()))]
async fn run_service(service: HashMap<String, Service>, socket_path: PathBuf) -> Result<()> {
    // No services to register
    if service.is_empty() {
        return Err(anyhow::anyhow!("No services provided to run"));
    }

    // Ensure the parent directory for the socket exists.
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await.context(format!(
            "Failed to create socket parent directory: {parent:?}"
        ))?;
    }

    // Remove any stale socket before binding.
    if socket_path.exists() {
        tokio::fs::remove_file(&socket_path).await.context(format!(
            "Failed to remove existing socket file: {socket_path:?}"
        ))?;
    }

    let sock_addr = format!("unix://{}", &socket_path.display());
    let mut server = TtrpcServer::new()
        .bind(&sock_addr)
        .context(format!("Failed to bind to socket: {sock_addr}"))?
        .register_service(service);
    info!("Successfully bound to socket and registered services: {sock_addr}");

    // Ensure socket exists and has correct permissions
    {
        // Verify socket was created
        if !socket_path.exists() {
            return Err(anyhow::anyhow!(
                "Socket file was not created during bind operation"
            ));
        }

        // Set socket permissions
        let perms = std::fs::Permissions::from_mode(0o666);
        tokio::fs::set_permissions(&socket_path, perms)
            .await
            .context(format!(
                "Failed to set permissions on socket: {socket_path:?}"
            ))?;

        info!("Set socket permissions to 0666");

        // Verify the socket has correct permissions
        let metadata = tokio::fs::metadata(&socket_path).await?;
        let file_perms = metadata.permissions();
        info!(
            "Socket file confirmed with permissions: {:o}",
            file_perms.mode() & 0o777
        );
    }

    info!("TTRPC server loop starting...");
    if let Err(e) = server.start().await {
        // Clean up socket when server shutdown
        if socket_path.exists() {
            if let Err(e) = tokio::fs::remove_file(&socket_path).await {
                error!(error = ?e, "Failed to remove socket file during cleanup");
            } else {
                info!(info = ?socket_path, "Cleaned up socket file");
            }
        }
        return Err(anyhow!("TTRPC server start failed with error: {e:?}"));
    }

    // Graceful shutdown signal handling
    // SIGINT (`Ctrl+C`)
    let mut sigint =
        signal(SignalKind::interrupt()).context("Failed to register SIGINT handler")?;
    // SIGTERM (`systemctl stop xxx`)
    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;
    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
            server.shutdown().await?;
        },
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown...");
            server.shutdown().await?;
        }
    }
    tokio::fs::remove_file(&socket_path).await?;

    info!("Service shutdown complete.");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup panic hook to ensure panics are logged
    std::panic::set_hook(Box::new(|panic_info| {
        error!(panic_info = %panic_info, "A task panicked");
    }));

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .init();

    let cli = Cli::parse();
    info!("Starting guest-services with command: {:?}", cli.command);

    match run(cli).await {
        Ok(_) => {
            info!("Service exited successfully");
            Ok(())
        }
        Err(e) => {
            error!(error = ?e, "Service failed");
            Err(e)
        }
    }
}

#[instrument(skip_all, fields(command = ?cli.command))]
async fn run(cli: Cli) -> Result<()> {
    // Extract common parameters
    let (socket, config_dir, service_name) = match &cli.command {
        Commands::ImagePull { socket, config_dir } => {
            (socket.clone(), config_dir.clone(), "ImagePull")
        }
        Commands::SealedSecrets { socket, config_dir } => {
            (socket.clone(), config_dir.clone(), "SealedSecrets")
        }
        Commands::SecureMount { socket, config_dir } => {
            (socket.clone(), config_dir.clone(), "SecureMount")
        }
        Commands::GetResource { socket, config_dir } => {
            (socket.clone(), config_dir.clone(), "GetResource")
        }
    };

    info!(
        "Initializing {service_name} service with socket: {socket:?} and config_dir: {config_dir:?}"
    );

    // Initialize CDH configuration
    let cdh_config = CdhConfig::new(Some(config_dir.display().to_string()))
        .context("Failed to initialize CDH configuration")?;

    info!("CDH configuration initialized successfully");

    // Create server instance
    let server_instance = Arc::new(
        Server::new(&cdh_config)
            .await
            .context("Failed to create main Server instance")?,
    );

    info!("Server instance created successfully");

    // Create the appropriate service based on command
    let service = match cli.command {
        Commands::ImagePull { .. } => {
            info!("Creating ImagePull ttrpc service");
            let svc = api_ttrpc::create_image_pull_service(server_instance);
            info!("ImagePull service created with {} service(s)", svc.len());
            svc
        }
        Commands::SealedSecrets { .. } => {
            info!("Creating SealedSecrets ttrpc service");
            let svc = api_ttrpc::create_sealed_secret_service(server_instance);
            info!(
                "SealedSecrets service created with {} service(s)",
                svc.len()
            );
            svc
        }
        Commands::SecureMount { .. } => {
            info!("Creating SecureMount ttrpc service");
            let svc = api_ttrpc::create_secure_mount_service(server_instance);
            info!("SecureMount service created with {} service(s)", svc.len());
            svc
        }
        Commands::GetResource { .. } => {
            info!("Creating GetResource ttrpc service");
            let svc = api_ttrpc::create_get_resource_service(server_instance);
            info!("GetResource service created with {} service(s)", svc.len());
            svc
        }
    };

    // Validate that one more services were created
    if service.is_empty() {
        return Err(anyhow::anyhow!(
            "Failed to create any services - service map is empty"
        ));
    }

    info!("Service creation completed, starting server...");

    // Start the service and run until shutdown
    run_service(service, socket).await
}
