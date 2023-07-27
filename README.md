# hacktools
A crate for rust consisting of functions that can be used by red teamers and hackers alike.
# Functions
At the moment there is little functions but more will be on the way.

The first is the "scan" function which is at the moment a system call that uses nmap to scan the port. 

You can use in your code like:
```rust
use hacktools::nmap_scan;

fn main() {
  nmap_scan("IP", Port);
}
//It only scans one port at a time as to be quiter. I will work more on this though
```

The second is the "dirf" function which I have created to try to be like the popular kali command dirb.

You can use it like:
```rust
use hacktools::dirf;

fn main() {
  dirf("https://example.com", "wordlist.txt");
}
```
The get function is for you to use on something like a blocked docker container and other things.

It can be used like:
```rust
use hacktools::get;

fn main() {
  get("cat", &["/etc/passwd"])?;
  //using this function in the &[] use another comma and "" for each space in your command.
}
```
The next function is the "shell" command which can be used to generate and execute shellcode.

Will be used as:
```rust
use hacktools::{shell, tools::execute_shellcode}
fn main() {
  shell("string", execute_shellcode);
  //When ran execute_shellcode will ask you what file path to run on.
}
```
The scan function unlike the "nmap_scan" can scan a port without the nmap command and is blazingly fast.
It has no version detection but will be useful to get ports in bulk.

You will use it like:
```rust
use hacktools::scan;
use std::time::Duration;
fn main() {
  scan("127.0.0.1", 80..81, Duration::new(5, 0));
}
//you can scan multiple by doing something like 0..255 but if you want only one port remember to do the port number .. one number after.
//To be helpful using the Colorized package I have added color red for closed green for open so your not stuck looking through all ports.
```

The function "press_scan" which is used to open a wordpress site and use common hidden urls for recon.

Will be used as:
```rust
use hacktools::press_scan;
fn main() {
  press_scan("https://wordpress.com", 0);
/* Options 0-8:
   "/wordpress/xmlrpc.php",
    "/wp-content/uploads/",
    "wp-json/wp/v2/users",
    "/wp-json/wp/v2/users/1",
    "/wp-json/?rest_route=/wp/v2/users/",
    "/wp-json/?rest_route=/wp/v2/users/1",
    "/?author=1",
    "/wp-login.php",
    "/wp-config.PhP"
*/
}
```
There is now also "forbid()". This allows you to check alternate pathways for a 403 forbidden.

This is the garbage port to rust from iamj0ker's very useful shell script.

You can use like:
```rust
use hacktools::forbid;
fn main() {
       forbid("http://example.com", "secret");
}
```
"Msf" is a fast way to use msfvenom for quick shellcode and exploits through metasploit.

Use case:
```rust
use hacktools::msf;
 fn main() -> Result<(), io::Error> {
     msf("exploit", "ip", port, "format", "Name of File");
     //format is for what it is etc: Rust, Python, C
     Ok(())
 }
 ```
# Reminder
please remember that at this time this is very unfinished and I will be adding to this. 

I know you all have ideas so please don't hesitate to tell me.
