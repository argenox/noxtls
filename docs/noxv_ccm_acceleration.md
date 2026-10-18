# Optional bounded NoxV CCM acceleration

`NOXTLS_CFG_FEATURE_NOXV_CCM_ACCEL` defaults to OFF. It requires NoxV hardware
acceleration, AES-128 and CCM. Direct macro users select
`NOXTLS_FEATURE_NOXV_CCM_ACCEL=1` with those dependencies.

The port accepts AES-128, a 13-byte nonce, one-byte AAD, four-byte MIC and
0..16 plaintext octets. Other valid requests return NOT_SUPPORTED from the
port and use the existing public CCM implementation. ECB/CBC/CTR mode hooks
are not enabled by this selection.

One interrupt-protected transaction loads the key once, computes CBC-MAC and
CTR, and erases its temporary state. Decryption publishes plaintext only after
checking all MIC bytes. A hardware error propagates, erases output and never
falls back. Admission and each block have bounded polling. Each START clears
previous completion and checks START_WHILE_BUSY, because the hardware address
resolver can arbitrate independently of CPU interrupts. A denied START must
not consume stale DONE or stale ciphertext.

Native regression targets compile the production CCM dispatcher and actual
NoxV port against injected MMIO, with the feature on and off. Checked-in
vectors were generated independently using Python cryptography AESCCM and
AES ECB. They cover 0/1/8/15/16/17/27/28-byte messages, two keys, fallback,
in-place and nonce/output aliasing, individual bad MIC bytes, output canaries,
no plaintext publication before authentication, each block timeout, busy
admission and denied START with stale DONE. Regenerate only with
`python tests/regression/generate_noxv_ccm_vectors.py`.

Configure with `-DNOXTLS_BUILD_REGRESSION_TESTS=ON -DBUILD_TESTS=OFF
-DBUILD_APPLICATIONS=OFF`, build, then run CTest. The regression MMIO seam is
native-only; it does not enable hardware memory access in other tests.

The original KC705 128-MHz bench measured an experimental 27-byte admitted
transaction at 180.1 us of interrupt masking, so that geometry was removed
before connected testing. Eight-byte public-vector calls improved from about
229/269..315 us encrypt/decrypt to 144/152 us. These are task walltimes, not
proof of radio ISR turnaround. The option remains experimental and default-off:
measure the complete radio response, IRQ latency and throughput on the target.
This change does not establish BLE PHY or RF qualification.
