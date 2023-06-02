//!
//! Integration test for simply logging in and out of MEGA.
//!

use std::env;

#[tokio::test]
async fn login_and_logout_test() {
    let email = env::var("MEGA_EMAIL").expect("missing MEGA_EMAIL environment variable");
    let password = env::var("MEGA_PASSWORD").expect("missing MEGA_PASSWORD environment variable");
    let mfa = env::var("MEGA_MFA").ok();

    let http_client = reqwest::Client::new();
    let mut mega = mega::Client::builder().build(http_client).unwrap();

    mega.login(&email, &password, mfa.as_deref())
        .await
        .expect("could not log in to MEGA");

    mega.logout().await.expect("could not log out from MEGA");
}
