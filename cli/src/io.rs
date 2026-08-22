use std::io::Write;
use std::io;
use databoxer_core::logs::LogType;

pub fn prompt(prompt_text: &str) -> io::Result<String> {
    let mut stdout = io::stdout().lock();
    write!(stdout, "[{}] {}: ", LogType::INPUT.icon(), prompt_text)?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    println!();

    Ok(input.trim().to_string())
}
