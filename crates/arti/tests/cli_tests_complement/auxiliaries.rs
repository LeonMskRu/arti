use assert_cmd::Command;

pub fn command() -> Command {
    Command::cargo_bin("arti").unwrap()
}
