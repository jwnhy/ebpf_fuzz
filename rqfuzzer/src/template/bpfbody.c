#include "bpfheader.h"
// declared here, defined later
struct bpf_insn bpf_prog[BPF_MAX_INSNS];

// currently only ringbuf
int create_bpf_map(context_t *ctx) {
  int ret = 0;
  ret = bpf_create_map(BPF_MAP_TYPE_ARRAY, 4, 4, PAGE_SIZE);
  if (ret < 0) {
    printf("%s", "[BPF_GUEST] map creation failed\n");
    return ret;
  }
  ctx->ringbuf_fd = ret;
  printf("[BPF_GUEST] map created with fd %d\n", ret);
  return 0;
}

static inline int insn_add_one(context_t *ctx, struct bpf_insn insn) {
  int start = ctx->insn_idx;
  int end = start + 1;
  if (end > ctx->insn_max) {
    return -1;
  }

  ctx->prog[start] = insn;
  ctx->insn_idx = end;
  return 0;
}

static inline int insn_add(context_t *ctx, struct bpf_insn *src_insn,
                           int src_insn_count) {
  int err = 0;

  for (int i = 0; i < src_insn_count; i++) {
    err = insn_add_one(ctx, src_insn[i]);
    if (err < 0)
      return -1;
  }

  return 0;
}

// gen [min, max] inclusive
static inline long randint(long min, long max) {
  return rand() % (max - min + 1) + min;
}

static inline long rand64() { return randint(0, INT64_MAX); }

static inline int rand32() { return randint(0, INT32_MAX); }

static inline int gen_get_map_ptr(context_t *ctx) {
  struct bpf_insn map_p[] = {
      GET_MAP_ADDR(ctx->ringbuf_fd, ctx->ringbuf_reg),
  };

  return insn_add(ctx, map_p, ARRAY_CNT(map_p));
}


static inline int gen_alu_insn(context_t *ctx) {
  int reg1 = randint(ctx->min_scalar_reg, ctx->max_scalar_reg);
  int reg2 = randint(ctx->min_scalar_reg, ctx->max_scalar_reg);

  int is_imm = rand32() % 2;
  int is_64 = rand32() % 2;
  int imm_v;

  int op_idx = randint(0, ARRAY_CNT(alu_ops_codes) - 1);
  int op = alu_ops_codes[op_idx];
  struct bpf_insn insn;

  if (is_imm)
    imm_v = rand64();
  if (!is_64)
    imm_v = imm_v & 0xffffffff;

  if (is_64 && is_imm)
    insn = BPF_ALU64_IMM(op, reg1, imm_v);
  else if (is_64 && !is_imm)
    insn = BPF_ALU64_REG(op, reg1, reg2);
  else if (!is_64 && is_imm)
    insn = BPF_ALU32_IMM(op, reg1, imm_v);
  else if (!is_64 && !is_imm)
    insn = BPF_ALU32_REG(op, reg1, reg2);

  return insn_add_one(ctx, insn);
}

static inline int gen_jmp_insn(context_t *ctx) {
  int reg1 = randint(ctx->min_scalar_reg, ctx->max_scalar_reg);
  int reg2 = randint(ctx->min_scalar_reg, ctx->max_scalar_reg);

  int is_imm = rand32() % 2;
  int is_64 = rand32() % 2;
  int imm_v;

  int op_idx = randint(0, ARRAY_CNT(jmp_ops_codes) - 1);
  int op = alu_ops_codes[op_idx];

  int insn_idx = ctx->insn_idx;
  int insn_max = ctx->insn_max;
  int off = randint(1, insn_max - insn_idx - 1); // only allow forward jump to avoid loop

  struct bpf_insn insn;

  if (is_imm)
    imm_v = rand64();
  if (!is_64)
    imm_v = imm_v & 0xffffffff;

  if (is_64 && is_imm)
    insn = BPF_JMP_IMM(op, reg1, imm_v, off);
  else if (is_64 && !is_imm)
    insn = BPF_JMP_REG(op, reg1, reg2, off);
  else if (!is_64 && is_imm)
    insn = BPF_JMP32_IMM(op, reg1, imm_v, off);
  else if (!is_64 && !is_imm)
    insn = BPF_JMP32_REG(op, reg1, reg2, off);

  return insn_add_one(ctx, insn);
}

static inline int gen_mov_insn(context_t *ctx) {
  int reg1 = randint(ctx->min_scalar_reg, ctx->max_scalar_reg);
  int reg2 = randint(ctx->min_scalar_reg, ctx->max_scalar_reg);

  int is_imm = rand32() % 2;
  int is_64 = rand32() % 2;
  int imm_v;
  struct bpf_insn insn;

  if (is_imm)
    imm_v = rand64();
  if (!is_64)
    imm_v = imm_v & 0xffffffff;

  if (is_64 && is_imm)
    insn = BPF_MOV64_IMM(reg1, imm_v);
  else if (is_64 && !is_imm)
    insn = BPF_MOV64_REG(reg1, reg2);
  else if (!is_64 && is_imm)
    insn = BPF_MOV32_IMM(reg1, imm_v);
  else if (!is_64 && !is_imm)
    insn = BPF_MOV32_REG(reg1, reg2);
  return insn_add_one(ctx, insn);
}

static inline int gen_end(context_t* ctx) {
  insn_add_one(ctx, BPF_MOV64_REG(BPF_REG_0, 0));
  insn_add_one(ctx, BPF_EXIT_INSN());
  return 0;
}

int main() {
  srand(time(NULL));
  context_t ctx = {
      .prog = bpf_prog,
      .insn_idx = 0,
      .insn_max = BPF_MAX_INSNS,
      .ringbuf_fd = 0,
      .ringbuf_reg = BPF_REG_9,
      .max_scalar_reg = BPF_REG_8,
      .min_scalar_reg = BPF_REG_4,
  };
  create_bpf_map(&ctx);
  gen_get_map_ptr(&ctx);
  gen_end(&ctx);
  int progfd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, bpf_prog, ctx.insn_idx, "");
  if (progfd < 0)
    printf("[BPF_GUEST] bpf program load failed with %s\n", strerror(errno));

  printf("%s", bpf_log_buf);

  int ret = bpf_prog_skb_run(progfd, "abcd", 4);
  if (ret < 0) 
    printf("[BPF_GUEST] bpf program run failed with %s\n", strerror(errno));
  return 0;
}
