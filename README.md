# NAPI NaCl plugin

This package gives to Node, via NAPI, a Rust implementation of encryption utilities found in [ecma-nacl](https://github.com/3nsoft/ecma-nacl/). Native cryptors utilize parallel execution, making it desirable in systems like [PrivacySafe](https://github.com/PrivacySafe/privacysafe-platform-electron).

## Building

Rust targets should be installed, listed in `package.json`.

`npm ci` installs everything.

`npm run build-all` builds everyting.


# License

Code is provided here under GNU General Public License, version 3.
