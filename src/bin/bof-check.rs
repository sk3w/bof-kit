use std::fs;
use std::path::PathBuf;
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Path to object file
    input: PathBuf,
}

fn main() {
    let args = Args::parse();
    let buffer = fs::read(&args.input).unwrap();
    println!("[*] Parsing {}", &args.input.display());
    bof_kit::parse(&buffer);
    println!("[*] Done!");
}