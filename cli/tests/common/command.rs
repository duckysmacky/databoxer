//! Contains a `DataboxerCommand` struct used to test the behavior of the CLI application. The
//! returned Output should be used to determine if the test was successful or not

use std::{
    ffi::OsStr,
    path::PathBuf,
    process::{Command, Output},
};

use super::PASSWORD;

/// Represents the `databoxer [arg]...` command. Acts like a wrapper for the `Command` type
pub struct DataboxerCommand {
    command: Command,
}

impl DataboxerCommand {
    /// Creates a new instance of a databoxer executable command for later use in tests
    pub fn new(subcommand: &str, needs_password: bool) -> Self {
        let path = PathBuf::from(env!("CARGO_BIN_EXE_databoxer"));
        let mut command = Command::new(path);
        
        command
            .arg("--verbose")
            .args(subcommand.split_ascii_whitespace());
        
        if needs_password {
            command.arg("--password").arg(PASSWORD);
        }
        
        Self { command }
    }

    /// Adds an argument to the command. Can be chained
    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.command.arg(arg);
        self
    }

    /// Executes the command and fetches the result. Will panic and fail test if failed to execute
    pub fn execute(mut self) -> Output {
        println!("Executing: {:?}", &self.command);
        match self.command.output() {
            Ok(output) => output,
            Err(err) => panic!("Failed to execute {:?}: {:?}", &self.command, err)
        }
    }
}

/// Prints formatted command output
pub fn print_output(output: &Output) {
    println!("Exit code ({})", output.status);

    let stdout = &output.stdout;
    if !stdout.is_empty() {
        println!("Stdout:\n{}", std::str::from_utf8(&stdout).unwrap());
    }

    let stderr = &output.stderr;
    if !stderr.is_empty() {
        println!("Stderr:\n{}", std::str::from_utf8(&stderr).unwrap());
    }
}
