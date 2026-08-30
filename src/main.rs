use std::{env, fs, path::PathBuf, process::ExitCode};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Parser, Subcommand};
use grey_signal::{admit, AdmissionMetadata};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Parser)]
#[command(name = "grey-signal")]
#[command(about = "Grey Signal protocol tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Admit {
        #[arg(long, default_value = "SIGNAL_ENVELOPE_B64")]
        input_env: String,
        #[arg(long)]
        registry_dir: PathBuf,
        #[arg(long)]
        policy_commit: String,
        #[arg(long)]
        workflow_run_id: String,
        #[arg(long)]
        workflow_run_attempt: u64,
        #[arg(long)]
        admitted_at: String,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("grey-signal: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Admit {
            input_env,
            registry_dir,
            policy_commit,
            workflow_run_id,
            workflow_run_attempt,
            admitted_at,
            output,
        } => {
            let encoded = env::var(&input_env)?;
            let raw = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
            let admitted_at = OffsetDateTime::parse(&admitted_at, &Rfc3339)?;
            let record = admit(
                &raw,
                &registry_dir,
                admitted_at,
                AdmissionMetadata {
                    policy_commit,
                    workflow_run_id,
                    workflow_run_attempt,
                    admitted_at,
                },
            )?;
            let mut bytes = serde_json::to_vec_pretty(&record)?;
            bytes.push(b'\n');
            fs::write(&output, bytes)?;
            println!("admitted {}", record.event.id);
        }
    }
    Ok(())
}
