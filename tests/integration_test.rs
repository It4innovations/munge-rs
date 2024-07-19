use std::net::Ipv4Addr;

use munge_rs as munge;
use munge_rs::{MungeMac, MungeZip};

#[test]
fn munge_encode() {
    let test_json = r#"
    {
      "name": "test_user",
      "age": 30,
      "email": "test_user@example.com",
      "is_active": true,
      "roles": ["admin", "user"],
      "address": {
        "street": "123 Test St",
        "city": "Testville",
        "postal_code": "12345"
      },
      "projects": [
        {
          "name": "Project One",
          "status": "completed"
        },
        {
          "name": "Project Two",
          "status": "in_progress"
        }
      ]
    }
    "#;

    let out = munge::encode(test_json, None).unwrap();
    println!("Encoded credential: \n\t{}\n", out);
}

#[test]
fn munge_encode_w_ctx() {
    let test_json = r#"
    {
      "name": "test_user",
      "age": 30,
      "email": "test_user@example.com",
      "is_active": true,
      "roles": ["admin", "user"],
      "address": {
        "street": "123 Test St",
        "city": "Testville",
        "postal_code": "12345"
      },
      "projects": [
        {
          "name": "Project One",
          "status": "completed"
        },
        {
          "name": "Project Two",
          "status": "in_progress"
        }
      ]
    }
    "#;

    let mut ctx = munge::Context::new();

    // TODO: UPDATE
    // ctx.set_ctx_opt(MungeOption::Ttl, 1024)
    //     .expect("Failed to set TTL")
    //     .set_ctx_opt(MungeOption::ZipType, MungeZip::Bzlib as u32)
    //     .expect("Failed to set compression type");
    ctx.set_ttl(1024)
        .expect("Failed to set TTL")
        .set_zip(MungeZip::Zlib)
        .expect("Failed to set compression type");

    let out = munge::encode(test_json, Some(&ctx)).unwrap();
    println!("Encoded credential with custom context: \n\t{}\n", out);
}

#[test]
fn munge_encode_decode() {
    let test_json = r#"
    {
      "name": "test_user",
      "age": 30,
      "email": "test_user@example.com",
      "is_active": true,
      "roles": ["admin", "user"],
      "address": {
        "street": "123 Test St",
        "city": "Testville",
        "postal_code": "12345"
      },
      "projects": [
        {
          "name": "Project One",
          "status": "completed"
        },
        {
          "name": "Project Two",
          "status": "in_progress"
        }
      ]
    }
    "#;

    let mut ctx = munge::Context::new();
    let default_socket = ctx.socket().expect("Failed to get socket path.");

    ctx.set_socket(default_socket)
        .expect("Failed to set socket path")
        .set_zip(MungeZip::Zlib)
        .expect("Failed to set compression type")
        .set_mac(MungeMac::SHA512)
        .expect("Failed to set MAC");

    let encoded = munge::encode(test_json, Some(&ctx)).unwrap();
    println!("Encoded base64 String: \n\t{}\n", encoded);

    let decoded = munge::decode(encoded, Some(&ctx)).unwrap();
    let addr4 = ctx.addr4().unwrap();
    let ip4: Ipv4Addr = Ipv4Addr::from(addr4.to_be());
    let encode_time = ctx.encode_time().unwrap();
    println!(
        "\nDecoded credential info: \n\t{:?}\nFrom address: {} at {:?}\n",
        decoded, ip4, encode_time
    );
}
