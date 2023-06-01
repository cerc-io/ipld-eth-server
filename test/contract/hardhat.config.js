require("@nomiclabs/hardhat-waffle");

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async () => {
  const accounts = await ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */

const localNetwork = {
  url: process.env.ETH_ADDR || "http://127.0.0.1:8545",
  chainId: Number(process.env.ETH_CHAIN_ID) || 99,
};

if (process.env.DEPLOYER_PRIVATE_KEY) {
  localNetwork["accounts"] = [process.env.DEPLOYER_PRIVATE_KEY];
}

module.exports = {
  solidity: {
    version: "0.8.0",
    settings: {
      outputSelection: {
        '*': {
          '*': [
            'abi', 'storageLayout',
          ]
        }
      }
    }
  },
  networks: {
    local: localNetwork
  },
  defaultNetwork: "local"
};
