# zkbp

zkbp is an efficient Python interface for zero-knowledge proof (ZKP) development using the BN254 elliptic curve, built on top of `Ark-bn254` and `Secp256k1` libraries.

---

## 🔍 Project Description

This project provides a Python wrapper for the `zkbp` library, enabling:

- Zero-knowledge proof construction using **Sigma protocols**
- **Range proofs** and **Bulletproof-style extensions**
- Cryptographic primitives for secure and private ledger applications

The core implementation is based on **BN254** (Barreto–Naehrig curve), making it compatible with common zk tools and EVM.

---

## 📦 Use Cases

zkbp is particularly suited for:

- Exploring ZKP-based ledger applications
- Prototyping cryptographic workflows in Python
- Can be used directly with [PADL](https://github.com/jpmorganchase/PADL), a python ledger dev kit by applied-research at JPMorganChase.

---

## 🔧 Features

- Pythonic interface to `Ark-bn254` and `Secp256k1` libraries
- Direct access to ZK primitives and Sigma proof generation
- Extendable with advanced ZKP constructs

---

## 🚀 Getting Started

You can install or use the wrapped `zkbp` library in your Python projects. Example usage will be provided in future updates or within the `examples/` directory (if available).

---

## 📄 License

This software is licensed under the **Apache 2.0 License**. See the [LICENSE](py_zkbp/LICENSE) file for details.

> ⚠️ **Note:** This is **research code only** and not intended for production use.

---

## 🤝 Contributions

This project is open to feedback and academic collaboration. 