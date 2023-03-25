use pezzo::unix::Context;

extern crate pezzo;

fn main() {
    let ctx = Context::current().unwrap();

    ctx.escalate_permissions();
    ctx.check_file_permissions(ctx.exe());

    // ctx.authenticate();
}
