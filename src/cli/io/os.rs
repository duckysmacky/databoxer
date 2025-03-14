#[cfg(unix)]
mod unix {
    use std::{io, mem};
    use std::fs::File;
    use std::io::BufRead;
    use std::os::fd::RawFd;
    use std::os::unix::io::AsRawFd;
    use libc::{termios, tcgetattr, tcsetattr, ECHO, TCSANOW, ECHONL};
    
    const CURSOR_UP: &str = "\x1b[1A";
    const ERASE_LINE: &str = "\x1b[2K";

    pub fn read_hidden() -> io::Result<String> {
        fn init_term(file_desc: RawFd) -> io::Result<termios> {
            let mut term = mem::MaybeUninit::<termios>::uninit();
            unsafe { tcgetattr(file_desc, term.as_mut_ptr()); }
            Ok(unsafe { term.assume_init() })
        }
        
        let tty = File::open("/dev/tty")?;
        let file_desc = tty.as_raw_fd();
        let mut term = init_term(file_desc)?;
        
        unsafe {
            term.c_lflag &= !ECHO;
            term.c_lflag |= ECHONL;
            tcsetattr(file_desc, TCSANOW, &term);
        }
        
        let mut reader = io::BufReader::new(tty);
        let mut input = String::new();
        reader.read_line(&mut input)?;
        print!("{}{}", CURSOR_UP, ERASE_LINE); // clean trailing newline

        unsafe {
            term.c_lflag |= ECHO;
            tcsetattr(file_desc, TCSANOW, &term);
        }

        Ok(input.trim().to_string())
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, ENABLE_ECHO_INPUT};

    pub fn read_hidden() -> io::Result<String> {
        let handle = unsafe {
            GetStdHandle(STD_INPUT_HANDLE)
        };
        let mut mode: u32 = 0;

        unsafe {
            GetConsoleMode(handle, &mut mode);
            SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT);
        }

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        unsafe {
            SetConsoleMode(handle, mode);
        }

        Ok(input.trim().to_string())
    }
}

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;