extern crate munge_rs;

use std::path::PathBuf;

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
    ctx.set_socket(PathBuf::from("/usr/local/var/run/munge/munge.socket.2"))
        .expect("Failed to set the socket path.");

    ctx.set_ctx_opt(enums::MungeOption::TTL, 1024).unwrap();

    let out = munge::encode(test_json, Some(ctx)).unwrap();
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
    ctx.set_socket(PathBuf::from("/usr/local/var/run/munge/munge.socket.2"))
        .unwrap();
    let encoded = munge::encode(test_json, Some(ctx)).unwrap();

    let decoded = munge::decode(encoded).unwrap();
    println!("\nDecoded credential info: \n\t{:?}", decoded);
}