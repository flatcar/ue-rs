## How to run

For example:

```
mkdir --parents ./src/testdata
curl --output ./src/testdata/flatcar_test_update-oem-azure.gz \
  https://bincache.flatcar-linux.net/images/amd64/9999.9.9+kai-sign-test-oem-sysext/flatcar_test_update-oem-azure.gz

cargo build --bin crau_test --target-dir .
debug/crau_test ./src/testdata/flatcar_test_update-oem-azure.gz
```

## how to generate Rust code from protobuf

```
sudo apt install protobuf-compiler
cargo install protoc-bin-vendored

UPDATE_ENGINE_PATH=.../update_engine

protoc --rust_out . $UPDATE_ENGINE_PATH/update_metadata.proto \
  --proto_path $UPDATE_ENGINE_PATH/src/update_engine/
```
