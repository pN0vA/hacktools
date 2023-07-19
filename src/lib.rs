//! # HackTools
//! 
//! A suite of functions mostly made for "Red Teamers"
#![allow(dead_code)]

use memmap::MmapMut;
use std::fs::OpenOptions;
use std::io::Write;
use std::mem;
use std::io::Result;
use std::process::Command;
use std::io::{self, BufRead};
use reqwest::StatusCode;

pub use self::tools::dirf;
pub use self::tools::scan;
pub use self::tools::get;
pub use self::tools::shell;

pub mod tools {
    use std::process::Command;
    use std::io::{self, BufRead};
    use reqwest::StatusCode;
    use memmap::MmapMut;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem;
// Grabs output from running a command
// # Example: get("cat", &["/etc/passwd"])?;
// The &["1", "2", "3"] can take multiple arguments.
    pub fn get(command: &str, args: &[&str]) -> Result<(), io::Error> {
        let output = Command::new(command)
            .args(args)
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{}", stdout);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Command failed: {}", stderr);
        }

        Ok(())
    }
    pub fn string_to_shellcode(input: &str) -> Vec<u8> {
        let mut shellcode = Vec::new();

        for c in input.chars() {
            let encoded = format!("{:02x}", c as u32);
            let bytes = encoded.as_bytes();
            let byte = u8::from_str_radix(unsafe { std::str::from_utf8_unchecked(bytes) }, 16).unwrap();
            shellcode.push(byte);
        }

        shellcode
    }
// At the Moment only works in unix and runs in the shared memory folder /dev/shm but will change soon.
    pub fn execute_shellcode(shellcode: &[u8]) {
        println!("Please put file path of memory:");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to Read Line");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(choice)
            .expect("Failed to open file");

        file.write_all(shellcode).expect("Failed to write shellcode");

        let mmap = unsafe {
            MmapMut::map_mut(&file).expect("Failed to memory map")
        };

        let shellcode_fn: fn() = unsafe { mem::transmute(mmap.as_ptr()) };
        shellcode_fn();
    }
//#Example
//fn main() {
//   let input = "Hello, world!";
//    shell(input, execute_shellcode);
//}
    pub fn shell(input: &str, execute: fn(&[u8])) {
        let shellcode = string_to_shellcode(input);
        println!("Generated Shellcode: {:?}", shellcode);
        execute(&shellcode);
    }
// A scanner using the nmap package
// #Example: scan("127.0.0.1", 80);
    pub fn scan(ip: &str, port: u16) {
        let output = Command::new("nmap")
            .arg("-p")
            .arg(port.to_string())
            .arg(ip)
            .output()
            .expect("Failed to execute nmap command");

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{}", stdout);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Command failed: {}", stderr);
        }
    }

// A web directory finder like dirb
// # Example: dirf("https://example.com", "wordlist.txt");
    pub async fn dirf(url: &str, wordlist_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::open(wordlist_path)?;
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let word = line.map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to read line from wordlist: {}", e),
                )
            })?;

            let full_url = format!("{}{}", url, word);

            let response = reqwest::get(&full_url).await?;

            if response.status().is_success() {
                println!("Found: {}", full_url);
            }
        }

        Ok(())
    }
}
