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
# Reminder
please remember that at this time this is very unfinished and I will be adding to this. 

I know you all have ideas so please don't hesitate to tell me.
