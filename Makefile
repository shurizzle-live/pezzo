all:
	cargo build --release
	sudo /bin/sh -c 'rm -f pezzo && cp target/release/pezzo . && chown root pezzo && chmod u+s pezzo'

clean:
	sudo rm -f pezzo
