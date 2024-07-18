extern crate munge_rs;

use munge_rs::{enums, munge};

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

    let mut ctx = munge_rs::ctx::Context::new();

    ctx.set_ctx_opt(enums::MungeOption::TTL, 1024).unwrap();
    ctx.set_ctx_opt(enums::MungeOption::ZIP_TYPE, enums::MungeZip::Bzlib as u32)
        .unwrap();

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

    let mut ctx = munge_rs::ctx::Context::new();
    let default_socket = ctx.get_socket().expect("Failed to get socket path.");
    ctx.set_socket(default_socket)
        .expect("Failed to set socket path.");
    ctx.set_ctx_opt(enums::MungeOption::ZIP_TYPE, enums::MungeZip::Zlib as u32)
        .expect("Failed to set compression type");
    ctx.set_ctx_opt(
        enums::MungeOption::MAC_TYPE,
        enums::MungeMac::RIPEMD160 as u32,
    )
    .expect("Failed to set MAC");

    let encoded = munge::encode(test_json, Some(&ctx)).unwrap();

    println!("Encoded base64 String: \n\t{}\n", encoded);

    let decoded = munge::decode(encoded, Some(&ctx)).unwrap();
    println!("\nDecoded credential info: \n\t{:?}", decoded);
}
