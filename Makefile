all:
	cargo test

debug:
	cargo test -- --nocapture --test-threads=1

clean:
	cargo clean
