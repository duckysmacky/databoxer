use std::io;
use crate::Result;

pub fn get_hidden(prompt: &str) -> Result<String> {
    todo!()
}

pub fn get_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    let input = read_stdin()?;
    Ok(input)
}

fn read_stdin() -> io::Result<String> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(buffer.trim().to_string())
}