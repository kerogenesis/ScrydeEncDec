@echo off
echo   Building ScrydeEncDec (Release x86 MSVC)

rustup target add i686-pc-windows-msvc

set RUSTFLAGS=-C target-feature=+crt-static --remap-path-prefix %USERPROFILE%=~

cargo build --release --target i686-pc-windows-msvc
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Binary successfully compiled to:
    echo target\i686-pc-windows-msvc\release\scryde_encdec.exe
) else (
    echo.
    echo [ERROR] Build failed! Check Rust compiler errors.
    pause
)
