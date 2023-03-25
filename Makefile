all:
	cargo build --release
	sudo /bin/sh -c 'rm -f pezzo && cp target/release/pezzo . && chown root:root pezzo && chmod ug+s pezzo'

clean:
	sudo rm -f pezzo
