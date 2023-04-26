use std::io::Result;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn build_oidn() -> Result<String> {
    let out_dir = env::var("OUT_DIR").unwrap();

    cmake::Config::new("oidn")
        .define("CMAKE_BUILD_TYPE", "Release")
        .generator("Ninja")
        .build();

    Ok(out_dir)
}


fn gen(out_dir: &String) -> Result<()> {
    match env::var("GEN_BINDING") {
        Ok(_) => {}
        Err(_) => return Ok(()),
    }
    let bindings = bindgen::Builder::default()
        .header(format!("{}/include/OpenImageDenoise/oidn.h", out_dir))
        .allowlist_function("oidn.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .prepend_enum_name(false)
        .generate()
        .unwrap();
    bindings
        .write_to_file("src/binding.rs")
        .expect("Couldn't write bindings!");
    Ok(())
}

fn is_path_dll(path: &PathBuf) -> bool {
    let basic_check = path.extension().is_some()
        && (path.extension().unwrap() == "dll"
        || path.extension().unwrap() == "lib" // lib is also need on Windows for linking DLLs
        || path.extension().unwrap() == "so"
        || path.extension().unwrap() == "dylib");
    if basic_check {
        return true;
    }
    if cfg!(target_os = "linux") {
        if let Some(stem) = path.file_stem() {
            if let Some(ext) = PathBuf::from(stem).extension() {
                if ext == "so" {
                    return true;
                }
            }
        }
    }
    false
}

fn copy_dlls(src_dir: &PathBuf, dst_dir: &PathBuf) {
    let out_dir = src_dir.clone();
    for entry in std::fs::read_dir(out_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if is_path_dll(&path) {
            let copy_if_different = |src, dst| {
                let p_src = Path::canonicalize(src).unwrap();
                let p_src = p_src.as_path();
                let p_dst = Path::new(&dst);
                let should_copy = !p_dst.exists();
                let check_should_copy = || -> Option<bool> {
                    let src_metadata = fs::metadata(p_src).ok()?;
                    let dst_metadata = fs::metadata(p_dst).ok()?;
                    Some(src_metadata.modified().ok()? != dst_metadata.modified().ok()?)
                };
                let should_copy = should_copy || check_should_copy().unwrap_or(true);
                if should_copy {
                    std::fs::copy(p_src, p_dst).unwrap();
                }
            };
            {
                let dest = dst_dir.clone().join(path.file_name().unwrap());
                copy_if_different(&path, dest);
            }
            {
                let dest = dst_dir.clone().join("deps").join(path.file_name().unwrap());
                copy_if_different(&path, dest);
            }
            {
                let dest = dst_dir
                    .clone()
                    .join("examples")
                    .join(path.file_name().unwrap());
                copy_if_different(&path, dest);
            }
        }
    }
}

fn prebuild_available() -> bool {
    if cfg!(target_arch = "x86_64") && (cfg!(target_os = "windows") || cfg!(target_os = "linux")) {
        true
    } else {
        false
    }
}

fn download_oidn() {
    let linux_url = r#"https://github.com/OpenImageDenoise/oidn/releases/download/v1.4.3/oidn-1.4.3.x86_64.linux.tar.gz"#;
    let windows_url =
        r#"https://github.com/OpenImageDenoise/oidn/releases/download/v1.4.3/oidn-1.4.3.x64.vc14.windows.zip"#;
    let source_url = r#"https://github.com/OpenImageDenoise/oidn/releases/download/v1.4.3/oidn-1.4.3.x64.vc14.windows.zip"#;
    let out_dir = "oidn";
    if prebuild_available() {
        let url = if cfg!(target_os = "windows") {
            windows_url
        } else {
            linux_url
        };
        let filename = if cfg!(target_os = "windows") {
            "oidn.zip"
        } else {
            "oidn.tar.gz"
        };
        Command::new("curl")
            .arg("-L")
            .arg(url)
            .arg("--output")
            .arg(filename)
            .output()
            .unwrap();
        std::fs::create_dir_all(&out_dir).unwrap();
        Command::new("tar")
            .args(["-zxvf", filename, "-C", &out_dir, "--strip-components=1"])
            .output()
            .unwrap();
    } else {
        Command::new("curl")
            .arg("-L")
            .arg(source_url)
            .arg("--output")
            .arg("oidn.zip")
            .output()
            .unwrap();
        std::fs::create_dir_all(&out_dir).unwrap();
        Command::new("tar")
            .args([
                "-zxvf",
                "oidn.zip",
                "-C",
                &out_dir,
                "--strip-components=1",
            ])
            .output()
            .unwrap();
    }
}
fn build_oidn_from_source() -> Result<()> {
    let out_dir = build_oidn()?;
    gen(&out_dir)?;
    let out_dir = env::var("OUT_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}/bin/", out_dir);
    println!("cargo:rustc-link-search=native={}/lib/", out_dir);
    println!("cargo:rustc-link-lib=dylib=OpenImageDenoise");
    let out_dir = PathBuf::from(out_dir);
    let comps: Vec<_> = out_dir.components().collect();
    let dst_dir = PathBuf::from_iter(comps[..comps.len() - 3].iter());

    let get_dll_dir = |subdir| {
        let dll_dir = out_dir.clone().join(subdir);
        let dll_dir = PathBuf::from(dll_dir);
        fs::canonicalize(dll_dir).unwrap()
    };

    copy_dlls(&get_dll_dir("lib"), &dst_dir);
    if cfg!(target_os = "windows") {
        copy_dlls(&get_dll_dir("bin"), &dst_dir);
    }
    Ok(())
}

fn prebuild() -> Result<()> {
    gen(&"oidn".to_string())?;
    println!("cargo:rustc-link-search=native=oidn/bin/");
    println!("cargo:rustc-link-search=native=oidn/lib/");
    println!("cargo:rustc-link-lib=dylib=OpenimageDenoise");

    let get_dll_dir = |subdir: &str| {
        let dll_dir = PathBuf::from("oidn").join(subdir);
        fs::canonicalize(dll_dir).unwrap()
    };
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);
    let out_dir = fs::canonicalize(out_dir).unwrap();
    let comps: Vec<_> = out_dir.components().collect();
    let out_dir = PathBuf::from_iter(comps[..comps.len() - 3].iter());

    copy_dlls(&get_dll_dir("lib"), &out_dir);
    if cfg!(target_os = "windows") {
        copy_dlls(&get_dll_dir("bin"), &out_dir);
    }
    Ok(())
}

fn main() -> Result<()> {
    download_oidn();
    if prebuild_available() {
        prebuild()?;
    } else {
        build_oidn_from_source()?;
    }
    Ok(())
}