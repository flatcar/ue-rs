use std::error::Error;

use hard_xml::XmlRead;
use omaha;

const RESPONSE_XML: &'static str =
r#"<?xml version="1.0" encoding="UTF-8"?>
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
    println!("{:#?}", omaha::Response::from_str(RESPONSE_XML)?);
    Ok(())
}
