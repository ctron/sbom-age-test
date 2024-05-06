mod db;
mod rel;

use crate::db::Database;
use serde_json::Value;
use spdx_rs::models::SPDX;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use tokio::task::spawn_blocking;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_log() {
    tracing_subscriber::registry()
        // Filter spans based on the RUST_LOG env var.
        .with(tracing_subscriber::EnvFilter::from_default_env())
        // Send a copy of all spans to stdout as JSON.
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_level(true)
                .compact(),
        )
        // Install this registry as the global tracing registry.
        .try_init()
        .expect("error initializing logging");
}

#[tokio::main]
async fn main() {
    init_log();
    run().await.unwrap();
}

async fn run() -> anyhow::Result<()> {
    let mut db = Database::new("host=localhost port=5433 user=postgres password=postgres").await?;
    // db.execute(r#"LOAD 'age'"#, &[]).await?;
    // db.execute(r#"SET search_path = ag_catalog, "$user", public"#, &[]).await?;

    for entry in walkdir::WalkDir::new("data") {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".bz2") {
            continue;
        }

        process(&mut db, entry.path()).await?;
    }

    Ok(())
}

async fn process(db: &mut Database, file: &Path) -> anyhow::Result<()> {
    if !file
        .file_name()
        .unwrap_or_else(|| file.as_os_str())
        .to_string_lossy()
        .starts_with("directory_")
    {
        return Ok(());
    }

    log::info!("Processing: {}", file.display());

    let file = file.to_path_buf();
    let sbom = spawn_blocking(move || {
        let processed = PathBuf::from(format!("{}.processed", file.display()));

        if processed.exists() {
            return Ok(serde_json::from_reader::<_, SPDX>(BufReader::new(
                File::open(processed)?,
            ))?);
        }

        let reader = BufReader::new(File::open(file)?);
        let reader = bzip2::bufread::BzDecoder::new(reader);
        let mut spdx = serde_json::from_reader(reader)?;
        fix_license(&mut spdx);
        let spdx: SPDX = serde_json::from_value(spdx)?;

        serde_json::to_writer(BufWriter::new(File::create(processed)?), &spdx)?;

        Ok::<_, anyhow::Error>(spdx)
    })
    .await??;

    log::info!("SBOM: {}", sbom.document_creation_information.document_name);

    db.ingest(sbom).await?;

    Ok(())
}

/// Check the document for invalid SPDX license expressions and replace them with `NOASSERTION`.
pub fn fix_license(json: &mut Value) -> bool {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str() {
                if let Err(err) = spdx_expression::SpdxExpression::parse(declared) {
                    log::warn!("Replacing faulty SPDX license expression with NOASSERTION: {err}");
                    package["licenseDeclared"] = "NOASSERTION".into();
                    changed = true;
                }
            }
        }
    }

    changed
}
