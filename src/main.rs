use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let ctx = Context::current().unwrap();

    let mut auth = ctx.authenticator().unwrap();

    auth.authenticate().unwrap();
}
