use hacktools::{*, tools::execute_shellcode};
fn main() {
    println!("Hello, world!");
    scan("127.0.0.1", 80);
    shell("hello world", execute_shellcode)
}
