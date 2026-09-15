QPADL Smart Contract PoC

Requirements:
solc, npm, hardhat, rust, cargo, napi

npm install --save-dev typescript@5.9.3 ts-node@10.9.2

npx napi build --release --platform

npx hardhat test test/ZKStark_update_rangehash_rust_state.ts
