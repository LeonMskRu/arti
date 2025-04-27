use assert_cmd::Command;

pub const ADDR_SIZE: usize = 56;
pub const CFG_PATH: &str = "./tests/testcases/hsc/conf/hsc.toml";

pub fn command() -> Command {
    Command::cargo_bin("arti").unwrap()
}
