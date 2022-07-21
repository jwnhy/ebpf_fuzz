#[allow(dead_code)]
pub mod rqemu;
pub mod genprog;
use rqemu::*;
use genprog::*;

fn main() {
    println!("Hello, world!");
    let qenv = QemuEnv::new();
    let mut inst = qenv.new_instance();
    println!("{:?}\n", inst);
    //inst.launch_and_attach();
    inst.launch();
    inst.print_cred();

    let mut filepath = String::new();
    println!("{}", std::env::current_dir().unwrap().display());
    loop {
        println!("Input file path to send file to /root:");
        std::io::stdin().read_line(&mut filepath).unwrap();   
        filepath = filepath.trim_matches('\n').to_string();
        inst.send_file(&filepath, "/home/test/");
    };
}
