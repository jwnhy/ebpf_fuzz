#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include "bpfdef.h"

int main(int argc, char* argv[]) {
  struct bpf_insn prog[] = {
    BPF_MOV64_IMM(BPF_REG_0, 0xdeadbeef),
    BPF_EXIT_INSN(),
  };
  return 0;
}
