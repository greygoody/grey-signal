use std::{env, fs, path::PathBuf, process::ExitCode};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use grey_signal::{
    AdmissionMetadata, Envelope, admit, generate_private_key, load_private_key, public_key,
    sign_envelope,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Parser)]
#[command(name = "grey-signal")]
#[command(about = "Grey Signal protocol tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    PublicKey {
        #[arg(long)]
        private_key: PathBuf,
    },
    Sign {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
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
        Command::Keygen { output } => {
            let public = generate_private_key(&output)?;
            println!("public_key={public}");
        }
        Command::PublicKey { private_key } => {
            let signing_key = load_private_key(&private_key)?;
            println!("public_key={}", public_key(&signing_key));
        }
        Command::Sign {
            private_key,
            input,
            output,
        } => {
            let raw = fs::read(input)?;
            let envelope: Envelope = serde_json::from_slice(&raw)?;
            let signing_key = load_private_key(&private_key)?;
            let envelope = sign_envelope(envelope, &signing_key)?;
            let mut bytes = serde_json::to_vec_pretty(&envelope)?;
            bytes.push(b'\n');
            fs::write(output, bytes)?;
            println!("signed {}", envelope.id);
        }
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
