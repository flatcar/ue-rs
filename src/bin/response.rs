use std::error::Error;

use hard_xml::XmlRead;

const RESPONSE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<response protocol="3.0" server="nebraska">
  <daystart elapsed_seconds="0"/>
  <app appid="{e96281a6-d1af-4bde-9a0a-97b76e56dc57}" status="ok">
    <updatecheck status="ok">
      <urls>
        <url codebase="https://update.release.flatcar-linux.net/amd64-usr/3374.2.0/"/>
      </urls>
      <manifest version="3374.2.0">
        <packages>
          <package name="flatcar_production_update.gz" hash="e2jgE9Ky/yeJ1q+GsDh/Hlb37cw=" size="360141900" required="true"/>
        </packages>
        <actions>
          <action event="postinstall" sha256="/kxm4FqtXuc0/qYLo9U2yccqNmEXMsWEdtKJ7nXtPaM=" DisablePayloadBackoff="true"/>
        </actions>
      </manifest>
    </updatecheck>
  </app>
</response>"#;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", RESPONSE_XML);
    println!();

    let resp = omaha::Response::from_str(RESPONSE_XML)?;

    println!("{:#?}", resp);
    println!();

    for app in &resp.apps {
        println!("app id {}:", app.id);

        let manifest = &app.update_check.manifest;
        println!("  version {}:", manifest.version);

        for pkg in &manifest.packages {
            println!("    package {}:", pkg.name);

            if let Some(h) = pkg.hash.as_ref() {
                println!("      sha1: {}", h)
            };

            if let Some(h) = pkg.hash_sha256.as_ref().or_else(|| {
                manifest
                    .actions
                    .iter()
                    .find(|a| a.event == omaha::response::ActionEvent::PostInstall)
                    .map(|a| &a.sha256)
            }) {
                println!("      sha256: {}", h);
            }

            println!();
            println!("      urls:");

            for url in &app.update_check.urls {
                println!("        {}", url.join(&pkg.name)?);
            }

            println!();
        }
    }

    Ok(())
}
