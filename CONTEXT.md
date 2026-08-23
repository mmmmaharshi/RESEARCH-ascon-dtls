# CONTEXT — ascon-dtls

## Vocabulary (canonical)

- **module**: compilation unit owning state / table (e.g. `wolfssl/wolfcrypt/mask_prf.{h,c}`).
- **interface**: public header API — `mask_prf.h` exports `mask_prf_derive` + `mask_prf_check_bound`; no other surface.
- **depth**: trimmed to two functions; one wire — deep not wide.
- **generic**: `domsep` table parameterizes one PRF over DTLS/QUIC/ESP/OSCORE; new context = new row + key.
- **colocate**: implementation lives next to `ascon.c` (same `wolfcrypt/src` dir), shares `AsconState` + `permutation`.

## Terms

- **Mask-PRF**: single-call keyed-sponge PRF `Mask_K(X)=trunc_t(P(domsep||K||X))`, generic `domsep` table, bound `q^2/2^192+q/2^128` tight `q/2^128`, flagship DTLS `RNDIMSK_` (`0x524E44494D534B5F`). See `wolfssl/wolfcrypt/mask_prf.h` (canonical table) and `docs/mask-prf-proof.md` Thm 1/1''.

## Canonical source

- `wolfssl/wolfcrypt/mask_prf.h` owns `mask_prf_domsep_table[4]`; `ascon.h:ASCON_MASK_DOMSEP` is alias to `table[0]` for compat.
- `tools/gen_domsep.py` generates `formal/coq/mask_prf_domsep.v` and `formal/easycrypt/mask_prf_domsep.ec` from same table.
