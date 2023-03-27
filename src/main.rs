fn main() {
    let args = doh_cli::get_args();
    if let Err(e) = doh_cli::run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
