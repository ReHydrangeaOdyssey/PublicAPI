#[tokio::main]
async fn main() -> std::process::ExitCode {
    match public_api::config::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("PublicAPI startup or server failure");
            std::process::ExitCode::FAILURE
        }
    }
}
