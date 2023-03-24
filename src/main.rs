use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let mut ctx = Context::current().unwrap();

    ctx.authenticate().unwrap();
}
