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

These contains the following meanings.

$$\begin{align}
(P.v[k]=0\wedge P.m[k]=0)&\triangleq P[k]=0 \\
(P.v[k]=1\wedge P.m[k]=0)&\triangleq P[k]=1 \\
(P.v[k]=0\wedge P.m[k]=1)&\triangleq P[k]=?
\end{align}$$
