use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let ctx = Context::current().unwrap();

    std::process::exit(if ctx.authenticate() { 0 } else { 1 });
}
