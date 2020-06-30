use serde_json::to_string_pretty;

use trojan::config::*;

#[test]
fn client_config() {
    let client_json = include_str!("json/client.json");
    let client_config: Config = serde_json::from_str(client_json).unwrap();
    assert_eq!(client_json, to_string_pretty(&client_config).unwrap());
}

#[test]
fn forward_config() {
    let forward_json = include_str!("json/forward.json");
    let forward_config: Config = serde_json::from_str(forward_json).unwrap();
    assert_eq!(forward_json, to_string_pretty(&forward_config).unwrap());
}

#[test]
fn nat_config() {
    let nat_json = include_str!("json/nat.json");
    let nat_config: Config = serde_json::from_str(nat_json).unwrap();
    assert_eq!(nat_json, to_string_pretty(&nat_config).unwrap());
}

#[test]
fn server_config() {
    let server_json = include_str!("json/server.json");
    let server_config: Config = serde_json::from_str(server_json).unwrap();
    assert_eq!(server_json, to_string_pretty(&server_config).unwrap());
}
