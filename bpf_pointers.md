# Pointers in BPF program

In BPF program, there is a **type** for each register, which changes and is
checked by the verification. If instruction is `BPF_MOV64_REG(BPF_REG_1, BPF_REG_5)`,
then type of `R5` is copied to `R1`.

All register are 64-bit.

- `R0` return register
- `R[1-5]` argument passing registers
- `R[6-9]` callee saved registers
- `R10` frame pointer (read-only)

At the start of BPF program, `R1` contains a pointer to `bpf_context` and has
type `PTR_TO_CTX`.

## eBPF pointer type list

- [x] `NOT_INIT`
- [x] `SCALAR_VALUE`
- [x] `PTR_TO_CTX`
- [x] `CONST_PTR_TO_MAP`
- [x] `PTR_TO_MAP_VALUE`
- [x] `PTR_TO_STACK`
- [ ] `PTR_TO_PACKET`
- [ ] `PTR_TO_PACKET_META`
- [ ] `PTR_TO_PACKET_END`
- [ ] `PTR_TO_FLOW_KEYS`
- [ ] `PTR_TO_SOCKET`
- [ ] `PTR_TO_SOCK_COMMON`
- [ ] `PTR_TO_TCP_SOCK`
- [ ] `PTR_TO_TP_BUFFER`
- [ ] `PTR_TO_XDP_SOCK`
- [ ] `PTR_TO_BTF_ID`
- [x] `PTR_TO_MEM`
- [ ] `PTR_TO_BUF`
- [ ] `PTR_TO_FUNC`
- [x] `PTR_TO_MAP_KEY`

## SCALAR_VALUE tracking

Tracking of `SCALAR_VALUE` consists of two parts, range and tristate number.
While the former tracks the range of one scalar registers, the latter tracks
how much knowledge does the verifier has over each **bit** of that register.

### Range tracking

`bpf_reg_state` constains the following fields.

- s64 smin_value: minimum possible (s64)value
- s64 smax_value: maximum possible (s64)value
- u64 umin_value: minimum possible (u64)value
- u64 umax_value: maximum possible (u64)value
- s32 s32_min_value: minimum possible (s32)value
- s32 s32_max_value: maximum possible (s32)value
- u32 u32_min_value: minimum possible (u32)value
- u32 u32_max_value: maximum possible (u32)value

These range values is updated through verification process.
Depending on the type of operands, these values are used in different ways.

In `pointer += K`, where an offset scalar is added to a pointer.

If the offset is known (a.k.a. without any unknown bit), then `dst_reg`
directly inherits all range values of `src_reg` with a new offset
`ptr_reg + off_reg->smin_val`.

If the offset has any unknown bit, it goes through a deduction process.

1. If either signed or unsigned addition overflows, saturates it.
2. Deduce new values if it doesn't overflows.
3. Deduce new `tnum` through `tnum_add(ptr_reg->var_off, off_reg->var_off)`.
4. Inherits whatever is left in `ptr_reg`.

When the pointer is used in memory access, only the `smin_value` is used,
which is `smin_value + off`.

**Remark I** Only `BPF_ADD` and `BPF_SUB` is allowed between pointer and scalar.

**Remark II** `tnum` are used to update these values in `__update_reg<bits>_bounds`.

### Tristate number tracking

[This paper](https://arxiv.org/pdf/2105.05398.pdf) introduces a way of tracking info
using tristate numbers in Linux, which has already been merged into the kernel.

Tristate numbers are implemented in Linux in the following way.

```c
struct tnum {
  u64 value;
  u64 mask;
};
```

These contain the following meanings.

$$\begin{align}
(P.v[k]=0\wedge P.m[k]=0)&\triangleq P[k]=0 \\
(P.v[k]=1\wedge P.m[k]=0)&\triangleq P[k]=1 \\
(P.v[k]=0\wedge P.m[k]=1)&\triangleq P[k]=\mu
\end{align}$$

This implementation of tristate number enables the verifier to perform
abstract interpretation of arithmetic operations.
Here is an example of `tnum_add(tnum a, tnum b)` inside Linux kernel.

```c
struct tnum tnum_add(struct tnum a, struct tnum b)
{
  u64 sm, sv, sigma, chi, mu;

  sm = a.mask + b.mask;
  sv = a.value + b.value;
  sigma = sm + sv;
  chi = sigma ^ sv;
  mu = chi | a.mask | b.mask;
  return TNUM(sv & ~mu, mu);
}
```

About why this works, please refer to the original paper or the following part.
Essentially, this is about the set ${p+q | p\in \gamma(P) \wedge q\in \gamma(Q)}$.

**Remark III** These `tnum` are used to update bounds like `smin_value`
only in `__update_reg_bounds`.

## Memory access tracking

The following applies to

- `PTR_TO_MEM`
- `PTR_TO_STACK`
- `PTR_TO_CTX`
- `PTR_TO_MAP_KEY`

As BPF program does not support global variable, all shared accesses are via
`struct bpf_context`. However, the check is complicated since it depends on
the program type. Basically, it will go through the following steps.

- `check_mem_access()` checks if it is leaking pointers (W & is_ptr) and `off`
    is positive, fixed and known.
- `check_ctx_access()` mark this access if it can be transformed into a narrower
    context access.
- `env->ops->is_valid_access()` makes sure it is a valid access in range (depending
    on type) if exists.

Here is an example of `sk_filter_is_valid_access`

```c
static bool sk_filter_is_valid_access(int off, int size,
              enum bpf_access_type type,
              const struct bpf_prog *prog,
              struct bpf_insn_access_aux *info)
{
  switch (off) {
  case bpf_ctx_range(struct __sk_buff, tc_classid):
  case bpf_ctx_range(struct __sk_buff, data):
  case bpf_ctx_range(struct __sk_buff, data_meta):
  case bpf_ctx_range(struct __sk_buff, data_end):
  case bpf_ctx_range_till(struct __sk_buff, family, local_port):
  case bpf_ctx_range(struct __sk_buff, tstamp):
  case bpf_ctx_range(struct __sk_buff, wire_len):
  case bpf_ctx_range(struct __sk_buff, hwtstamp):
    return false;
  }

  if (type == BPF_WRITE) {
    switch (off) {
    case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
      break;
    default:
      return false;
    }
  }

  return bpf_skb_is_valid_access(off, size, type, prog, info);
}
```

Similar checks is performed to `PTR_TO_MEM` with `check_mem_region_access()` and
`__check_mem_access`.

With `PTR_TO_STACK`, the verifier checks if it's inbound with `check_stack_access_within_bounds`
and then `update_stack_depth`. A special case here is that **helper function**
may also access stack, this is checked by `check_helper_mem_access`
when a helper call occurs.

As for `PTR_TO_MAP_KEY`, it is checked via `check_mem_region_access()` and write
to it is forbidden.

**Remark IV** All above types and `PTR_TO_MAP_VALUE` is checked by `check_mem_access()`.

## Map access tracking

`check_mem_access` is still in charge of checking `PTR_TO_MAP_VALUE`. Just with
a few additional steps.

- `check_mem_access()` checks if it is leaking pointers (W & is_ptr) and access types.
- `check_map_access_type()` checks if this access is allowed (R/W).
- `check_map_access()` checks if there exists spinlock or timer (both are
    forbidden via direct access)
- If this access is read-only and the pointer is known (indicated by `tnum`),
    then this register is marked as a known `SCALAR_VALUE`.
- Otherwise, it is tracked as an unknown register.

**Remark V** `CONST_MAP_PTR` is the pointer to the map structure, it may only
be loaded via `BPF_LD` with a non-standard 64-bit immediate. It is used in functions
like `bpf_map_lookup_elem()` as its arguments to retrieve map element.

