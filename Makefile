KERNEL_DIR = ./linux
ROOTFS_DIR = ./debian
FUZZER_DIR = ./rqfuzzer

all: build kernel rootfs rqfuzzer
	cd build && ./rqfuzzer

build:
	-mkdir build

kernel:
ifeq (,$(wildcard $(KERNEL_DIR)/arch/x86_64/boot/bzImage))
		cd $(KERNEL_DIR) && $(MAKE)
endif
	cp $(KERNEL_DIR)/arch/x86_64/boot/bzImage ./build/

rootfs:
ifeq (,$(wildcard $(ROOTFS_DIR)/stretch.img) ) 
		cd $(ROOTFS_DIR) && ./create-image.sh
endif
	cp $(ROOTFS_DIR)/stretch.img ./build/rootfs.img
	cp $(ROOTFS_DIR)/stretch.id_rsa ./build/

rqfuzzer:
	cd $(FUZZER_DIR) && cargo build --release
	cp $(FUZZER_DIR)/target/release/rqfuzzer ./build/
