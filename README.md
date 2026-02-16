# NAPI NaCl plugin

This package gives to Node, via NAPI, a Rust implementation of encryption utilities found in [ecma-nacl](https://github.com/3nsoft/ecma-nacl/). Native cryptors utilize parallel execution, making it desirable in systems like [PrivacySafe](https://github.com/PrivacySafe/privacysafe-platform-electron).

## Building

To use this repo, you need [Node.js](https://nodejs.org/).

Native module code is written in [Rust](https://rust-lang.org/), and uses [NAPI-RS](https://napi.rs/).

Cross compilation uses `--cross-compile` [flag](https://napi.rs/docs/cli/build#options) requiring presence of [zig](https://ziglang.org/). `rustup` targets should be added for cross-compilation.

Rust targets should be installed, listed in `package.json`.

`npm ci` installs everything.

`npm run build-all` builds everyting.


# License

Code is provided here under GNU General Public License, version 3.
