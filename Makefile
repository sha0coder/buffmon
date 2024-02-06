

all:
	CARGO_CFG_TARGET_OS=windows cargo build --target x86_64-pc-windows-gnu --release

