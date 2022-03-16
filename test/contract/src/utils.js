const { artifacts } = require("hardhat")
const { utils, BigNumber } = require("ethers")


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
