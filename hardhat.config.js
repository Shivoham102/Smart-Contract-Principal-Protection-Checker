require("@nomicfoundation/hardhat-toolbox");


module.exports = {
  solidity: {
  compilers: [
    { version: "0.8.20" },
    { version: "0.6.0" },
  ]
},

  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  }
};
