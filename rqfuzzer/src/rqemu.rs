use std::process::Command;

#[derive(Debug)]
pub enum QemuStatus {
    CONFIGED,
    INITED,
    RUNNING,
    CRASHED,
    FINISHED,
}

#[derive(Debug)]
pub struct QemuEnv<'a> {
    guestname: &'a str,   // username; default `root`
    uid: u32,             // uid; default `0`
    host_pubkey: &'a str, // path to id_*.pub; default `~/.ssh/id_ed25519.pub`
    qemu_exec: &'a str,   // path to qemu executable; default `/usr/bin/qemu-system-x86_64`

    memsz: usize, // memory size of the instance
    core: usize,  // core number of the instance

    bzimage: &'a str, // path to bzimage
    rootfs: &'a str,  // path to rootfs

    instances: Vec<QemuInstance<'a>>,
}

#[derive(Debug)]
pub struct QemuInstance<'a> {
    id: usize,
    status: QemuStatus,
    fwdport: u16,
    cmd: Command,
    env: &'a QemuEnv<'a>,
}

impl<'a> QemuEnv<'a> {
    pub fn new() -> Self {
        QemuEnv {
            guestname: "test",
            uid: 0,
            host_pubkey: "./stretch.id_rsa",
            qemu_exec: "/usr/bin/qemu-system-x86_64",
            memsz: 256,
            core: 1,
            bzimage: "./bzImage",
            rootfs: "rootfs.img",
            instances: vec![],
        }
    }

    pub fn new_instance(&'a self) -> QemuInstance<'a> {
        use portpicker::pick_unused_port;

        let fwdport = pick_unused_port().expect("no free port");
        let mut cmd = Command::new(self.qemu_exec);
        cmd.args(["-m", &self.memsz.to_string()])
            .args(["-smp", &self.core.to_string()])
            .args(["-kernel", &self.bzimage])
            .args([
                "-append",
                "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0",
            ])
            .args(["-drive", &format!("file={},format=raw", self.rootfs)])
            .args([
                "-net",
                &format!("user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{}-:22", fwdport),
            ])
            .args(["-net", "nic,model=e1000"])
            .args(["-enable-kvm", "--nographic", "-snapshot"]);
        let inst = QemuInstance {
            id: self.instances.len(),
            env: self,
            status: QemuStatus::CONFIGED,
            fwdport,
            cmd,
        };
        inst
    }
}

impl<'a> QemuInstance<'a> {
    pub fn launch(&mut self) {
        use std::process::Stdio;
        self.cmd.stdout(Stdio::null());
        self.cmd.stderr(Stdio::null());
        self.cmd.stdin(Stdio::null());
        self.cmd
            .spawn()
            .expect(&format!("fail to starting qemu: {}", self.id));
        self.status = QemuStatus::RUNNING;
    }

    pub fn launch_and_attach(&mut self) {
        let mut child = self
            .cmd
            .spawn()
            .expect(&format!("fail to starting qemu: {}", self.id));
        self.status = QemuStatus::RUNNING;
        child.wait().expect(&format!("fail to attach: {}", self.id));
    }

    pub fn exec_cmd(&mut self, cmd: &str) {
        use std::io::prelude::*;
        let sess = self.setup_session();
        let mut chan = sess
            .channel_session()
            .expect(&format!("fail to open channel: {}", self.id));
        chan.exec(cmd)
            .expect(&format!("fail to exec {}: {}", cmd, self.id));
        let mut s = String::new();
        chan.read_to_string(&mut s).unwrap();
        println!("{}", s);
        chan.wait_close()
            .expect(&format!("fail to close channel: {}", self.id));
        println!("{}", chan.exit_status().unwrap());
    }

    pub fn send_file(&mut self, local_path: &str, remote_path: &str) {
        use std::fs::read;
        use std::io::prelude::*;
        use std::path::Path;
        let sess = self.setup_session();
        let mut remote_file = sess
            .scp_send(
                Path::new(remote_path),
                0o644,
                Path::new(local_path).metadata().unwrap().len(),
                None,
            )
            .expect(&format!("fail to open remote file: {}", self.id));
        remote_file
            .write_all(&read(local_path).expect(&format!("fail to read local file: {}", self.id)))
            .expect(&format!("fail to upload file: {}", self.id));
    }

    fn setup_session(&mut self) -> ssh2::Session {
        use ssh2::Session;
        use std::net::TcpStream;
        use std::path::Path;

        let tcp = TcpStream::connect(&format!("127.0.0.1:{}", self.fwdport))
            .expect(&format!("fail to start tcp: {}", self.id));
        let mut sess = Session::new().expect(&format!("fail to start ssh session: {}", self.id));
        sess.set_tcp_stream(tcp);
        sess.handshake()
            .expect(&format!("handshake failed: {}", self.id));
        sess.userauth_pubkey_file(
            self.env.guestname,
            None,
            Path::new(self.env.host_pubkey),
            None,
        )
        .expect(&format!("auth failed: {}", self.id));
        sess
    }
}
