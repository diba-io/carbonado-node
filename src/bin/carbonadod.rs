use std::process;

use anyhow::Result;
use clap::Parser;
use flexi_logger::{colored_detailed_format, detailed_format, AdaptiveFormat, Logger};
use log::error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
/// Carbonado Node
enum Commands {
    /// Start storage provider node with configured frontends
    Start,
}

pub async fn try_main() -> Result<()> {
    match Commands::parse() {
        Commands::Start => carbonado_node::start().await?,
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Debug
    #[cfg(debug_assertions)]
    {
        let logger = Logger::try_with_str("trace, carbonado_node=trace, carbonado=trace")?
            .adaptive_format_for_stderr(AdaptiveFormat::Detailed)
            .adaptive_format_for_stdout(AdaptiveFormat::Detailed)
            .set_palette("196;208;10;7;8".to_owned())
            .format_for_files(detailed_format)
            .format_for_writer(colored_detailed_format);

        let handle = logger.start()?;

        if let Err(err) = try_main().await {
            error!("{}", err);
            err.chain()
                .skip(1)
                .for_each(|cause| eprintln!("Error: {cause}"));

            handle.flush();
            process::exit(1);
        }
    }

    // Release
    #[cfg(not(debug_assertions))]
    {
        let formatter = flexi_syslog::Formatter5424 {
            facility: syslog::Facility::LOG_USER,
            hostname: None,
            process: "basic".into(),
            pid: 0,
        };

        let sys_logger = syslog::unix(formatter).expect("Failed to init unix socket");

        let syslog_writer = flexi_syslog::log_writer::Builder::default()
            .max_log_level(log::LevelFilter::Info)
            .build(sys_logger);

        let logger = Logger::try_with_str("debug, carbonado=debug")?
            .adaptive_format_for_stderr(AdaptiveFormat::Detailed)
            .adaptive_format_for_stdout(AdaptiveFormat::Detailed)
            .set_palette("196;208;10;7;8".to_owned())
            .format_for_files(detailed_format)
            .format_for_writer(colored_detailed_format)
            .log_to_writer(Box::new(syslog_writer));

        let handle = logger.start()?;

        if let Err(err) = try_main().await {
            error!("{}", err);
            err.chain()
                .skip(1)
                .for_each(|cause| eprintln!("Error: {}", cause));

            handle.flush();
            process::exit(1);
        }
    }

    Ok(())
}
