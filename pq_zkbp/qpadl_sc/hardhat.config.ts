import { HardhatUserConfig, subtask } from "hardhat/config";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from "hardhat/builtin-tasks/task-names";
import "@nomicfoundation/hardhat-toolbox";
// Explicit re-import to guarantee chai matchers (revertedWith, emit,
// changeEtherBalances, BigInt equality, ...) are registered on the same
// chai instance the tests use.
import "@nomicfoundation/hardhat-chai-matchers";
import path from "path";

// Use the locally-installed `solc` npm package instead of letting Hardhat
// download soljson from binaries.soliditylang.org.
const LOCAL_SOLC_VERSION = "0.8.26";
const LOCAL_SOLC_LONG_VERSION = "0.8.26+commit.8a97fa7a";

subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args: { solcVersion: string }, _hre, runSuper) => {
  if (args.solcVersion === LOCAL_SOLC_VERSION) {
    const compilerPath = path.join(
      __dirname,
      "node_modules",
      "solc",
      "soljson.js"
    );
    return {
      compilerPath,
      isSolcJs: true, // pure-JS compiler from the npm package
      version: args.solcVersion,
      longVersion: LOCAL_SOLC_LONG_VERSION,
    };
  }
  return runSuper();
});

const config: HardhatUserConfig = {
  solidity: {
    version: LOCAL_SOLC_VERSION,
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 1   // Minimize code size (verification called rarely)
      },
      metadata: {
        bytecodeHash: "none"
      },
      evmVersion: "cancun" // Enables PUSH0, TSTORE/TLOAD, MCOPY
    }
  },
  networks: {
    hardhat: {
      blockGasLimit: 1_000_000_000,
      allowUnlimitedContractSize: true,
    },
  },
};

export default config;
