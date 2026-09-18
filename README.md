<p align="center">
  <img src="res/cover.png" alt="ScrydeEncDec" width="100%">
</p>

<p align="left">
  <img src="https://img.shields.io/badge/language-Rust-orange">
  <img src="https://img.shields.io/badge/platform-Windows%20x86-0078d4">
  <img src="https://github.com/kerogenesis/ScrydeEncDec/actions/workflows/release.yml/badge.svg">
  <img src="https://img.shields.io/badge/license-MIT-blue">
  <a href="https://github.com/kerogenesis/ScrydeEncDec/releases/download/v1.0.0/ScrydeEncDec_v1.0.0.zip"><img src="https://img.shields.io/github/v/release/kerogenesis/ScrydeEncDec"></a>
</p>

## Features
- The app works in the same way as the well-known mxencdec.
- It also lets you work with folders that have files in them.
- Uses multithreading for faster performance.

## Supported formats & headers
- Headers: 111, 120, 121, 211, 212, 413
- Extensions: dat, xdat, u, uax, ugx, uix, ukx, unr, usk, usx, utx, ini, int, ogg

## Usage

Just select your files or folders and drag them onto scryde_encdec.exe.

## Building

You can use build_release.bat script or run the following commands manually:
```sh
cargo build --release
```

Release file lands in `"target\i686-pc-windows-msvc\release\scryde_encdec.exe"`.
