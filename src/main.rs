mod cli;
mod config;
#[cfg(test)]
mod fake;
mod hook;
mod init;
mod scrub;
mod stats;

fn main() {
    std::process::exit(cli::run());
}
