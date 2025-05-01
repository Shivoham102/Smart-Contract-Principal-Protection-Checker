require("@nomicfoundation/hardhat-toolbox");


module.exports = {
  solidity: "0.8.28",  // Match your contract's pragma version
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};
