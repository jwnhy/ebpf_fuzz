#[allow(dead_code)]
pub mod rqemu;
use std::thread::sleep;
use std::time::Duration;
use rqemu::*;

fn main() {
    println!("Hello, world!");
    let mut qenv = QemuEnv::new();
    let mut inst = qenv.new_instance();
    let inst2 = qenv.new_instance();
    println!("{:?}\n{:?}", inst, inst2);
    inst.launch_and_attach();
    inst.launch();
    sleep(Duration::new(5, 0));
    inst.exec_cmd("ls /");
}
