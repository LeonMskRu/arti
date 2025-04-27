use assert_cmd::Command;

pub const ADDR_SIZE: usize = 56;

pub fn command() -> Command {
    Command::cargo_bin("arti").unwrap()
}
