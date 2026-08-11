#[cfg(target_os = "windows")]
fn main() {
    println!("cargo::rustc-link-arg=/DEBUG:NONE");

    let mut res = winres::WindowsResource::new();
    res.set_icon("res/app.ico");
    if let Err(e) = res.compile() {
        eprintln!("Failed to compile Windows resource: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {}
