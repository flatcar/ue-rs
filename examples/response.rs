use std::error::Error;

use anyhow::Context;
use hard_xml::XmlRead;
use omaha;

#[rustfmt::skip]
const RESPONSE_XML: &str =
r#"<?xml version="1.0" encoding="UTF-8"?>
<response protocol="3.0" server="nebraska">
  <daystart elapsed_seconds="0"/>
  <app appid="{e96281a6-d1af-4bde-9a0a-97b76e56dc57}" status="ok">
    <updatecheck status="ok">
      <urls>
        <url codebase="https://update.release.flatcar-linux.net/amd64-usr/3374.2.5/"/>
      </urls>
      <manifest version="3374.2.5">
        <packages>
          <package name="flatcar_production_update.gz" hash="quPS8xPVCw/HUCIZfKD4lt9kHr8=" size="364314900" required="true"/>
        </packages>
        <actions>
          <action event="postinstall" sha256="WR2cXX1kIaie+ElHh6ZxYVSOlOD2Ko/JQHvndGNhcMI=" DisablePayloadBackoff="true"/>
        </actions>
      </manifest>
    </updatecheck>
  </app>
</response>"#;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", RESPONSE_XML);
    println!();

    let resp = omaha::Response::from_str(RESPONSE_XML).context("failed to create response")?;

    println!("{:#?}", resp);
    println!();

    for app in &resp.apps {
        println!("app id {}:", app.id);

        let manifest = &app.update_check.manifest;
        println!("  version {}:", manifest.version);

        for pkg in &manifest.packages.packages {
            println!("    package {}:", pkg.name);

            #[rustfmt::skip]
            if let Some(h) = pkg.hash.as_ref() {
                println!("      sha1: {:?}", h);
            };

            #[rustfmt::skip]
            let hash_sha256 = pkg.hash_sha256
                .as_ref()
                .or_else(|| {
                    manifest.actions.actions.iter()
                        .find(|a| a.event == omaha::response::ActionEvent::PostInstall)
                        .map(|a| &a.sha256)
                });

            #[rustfmt::skip]
            hash_sha256
                .map(|h| {
                    println!("      sha256: {:?}", h);
                });

            println!();
            println!("      urls:");

            for url in &app.update_check.urls {
                println!(
                    "        {}",
                    url.join(&pkg.name).context(format!("failed to join URL with {:?}", pkg.name))?
                );
            }

            println!();
        }
    }

    Ok(())
}
