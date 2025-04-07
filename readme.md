# Signature Replay Attack Demo witth EIP-191 version 0x45

This repository demonstrates how a contract using insecure signature verification is vulnerable to replay attacks, and how EIP-191 verion 0x45 fixes it.

---

## 🔬 Tests

The test suite (`ReplayTest`) uses Foundry to simulate and compare behavior between `Vulnerable` and `Safe`.

Run the tests:

```bash
forge test -vvv --match-contract ReplayTest
```
