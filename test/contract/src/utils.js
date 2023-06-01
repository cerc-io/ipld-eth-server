const { artifacts } = require("hardhat")
const { utils, BigNumber } = require("ethers")
const { deployFactory, isDeployed } = require("solidity-create2-deployer");

// Hardcoded account which solidity-create2-deployer uses to deploy its factory
const CREATE2_FACTORY_ACCOUNT = '0x2287Fa6efdEc6d8c3E0f4612ce551dEcf89A357A';

async function getStorageLayout(contractName) {
  const artifact = await artifacts.readArtifact(contractName);
  const buildInfo = await artifacts.getBuildInfo(`${artifact.sourceName}:${artifact.contractName}`);

  if (!buildInfo) {
    throw new Error('storageLayout not present in compiler output.');
  }

  const output = buildInfo.output;
  const { storageLayout } = output.contracts[artifact.sourceName][artifact.contractName];

  if (!storageLayout) {
    throw new Error('Contract hasn\'t been compiled.');
  }

  return storageLayout;
};

async function getStorageSlotKey(contractName, variableName) {
  storageLayout = await getStorageLayout(contractName)

  const { storage } = storageLayout;
  const targetState = storage.find((state) => state.label === variableName);

  // Throw if state variable could not be found in storage layout.
  if (!targetState) {
    throw new Error('Variable not present in storage layout.');
  }

  key = utils.hexlify(BigNumber.from(targetState.slot));
  return key
};

async function deployCreate2Factory(provider, signer) {
  // Fund hardcoded account before deploying factory
  let tx = {
    to: CREATE2_FACTORY_ACCOUNT,
    value: utils.parseEther('0.01')
  }
  await signer.sendTransaction(tx).then(tx => tx.wait());

  const address = await deployFactory(provider);
  // solidity-create2-deployer doesn't await the deploy tx
  while (!await isDeployed(address, provider));
  return address;
}

module.exports = { getStorageSlotKey, deployCreate2Factory }
