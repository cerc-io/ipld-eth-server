const fastify = require('fastify')({ logger: true });
const hre = require("hardhat");

const {
  deployContract,
  isDeployed
} = require("solidity-create2-deployer");

const { getStorageSlotKey, deployCreate2Factory } = require('./utils');

const CREATE2_FACTORY_ADDRESS = '0x4a27c059FD7E383854Ea7DE6Be9c390a795f6eE3'

// readiness check
fastify.get('/v1/healthz', async (req, reply) => {
  reply
    .code(200)
    .header('Content-Type', 'application/json; charset=utf-8')
    .send({ success: true })
});

fastify.get('/v1/sendEth', async (req, reply) => {
  const to = req.query.to;
  const value = hre.ethers.utils.parseEther(req.query.value);

  const owner = await hre.ethers.getSigner();
  const tx = await owner.sendTransaction({to, value}).then(tx => tx.wait());

  return {
    from: tx.from,
    to: tx.to,
    txHash: tx.hash,
    blockNumber: tx.blockNumber,
    blockHash: tx.blockHash,
  }
});

function contractCreator(name) {
  return async (req, reply) => {
    const contract = await hre.ethers.getContractFactory(name);
    const instance = await contract.deploy();
    const rct = await instance.deployTransaction.wait();

    return {
      address: instance.address,
      txHash: rct.transactionHash,
      blockNumber: rct.blockNumber,
      blockHash: rct.blockHash,
    }
  }
}

function contractDestroyer(name) {
  return async (req, reply) => {
    const addr = req.query.addr;
    const contract = await hre.ethers.getContractFactory(name);
    const instance = contract.attach(addr);
    const rct = await instance.destroy().then(tx => tx.wait());

    return {
      blockNumber: rct.blockNumber,
    }
  }
}

fastify.get('/v1/deployContract', contractCreator("GLDToken"));
fastify.get('/v1/destroyContract', contractDestroyer("GLDToken"));

fastify.get('/v1/deploySLVContract', contractCreator("SLVToken"));
fastify.get('/v1/destroySLVContract', contractDestroyer("SLVToken"));

fastify.get('/v1/incrementCountA', async (req, reply) => {
  const addr = req.query.addr;

  const SLVToken = await hre.ethers.getContractFactory("SLVToken");
  const token = await SLVToken.attach(addr);

  const tx = await token.incrementCountA();
  const receipt = await tx.wait();

  return {
    blockNumber: receipt.blockNumber,
  }
});

fastify.get('/v1/incrementCountB', async (req, reply) => {
  const addr = req.query.addr;

  const SLVToken = await hre.ethers.getContractFactory("SLVToken");
  const token = await SLVToken.attach(addr);

  const tx = await token.incrementCountB();
  const receipt = await tx.wait();

  return {
    blockNumber: receipt.blockNumber,
  }
});

fastify.get('/v1/getStorageKey', async (req, reply) => {
  const contract = req.query.contract;
  const label = req.query.label;

  const key = await getStorageSlotKey(contract, label)

  return {
    key
  }
});

fastify.get('/v1/create2Contract', async (req, reply) => {
  const contract = req.query.contract;
  const salt = req.query.salt;

  const provider = hre.ethers.provider;
  const signer = await hre.ethers.getSigner();
  const isFactoryDeployed = await isDeployed(CREATE2_FACTORY_ADDRESS, provider);

  if (!isFactoryDeployed) {
    await deployCreate2Factory(provider, signer);
  }

  const contractFactory = await hre.ethers.getContractFactory(contract);
  const bytecode = contractFactory.bytecode;
  const constructorTypes = [];
  const constructorArgs = [];

  const createArgs = {
    salt,
    contractBytecode: bytecode,
    constructorTypes: constructorTypes,
    constructorArgs: constructorArgs,
    signer
  };
  const { txHash, address, receipt } = await deployContract(createArgs);
  const success = await isDeployed(address, provider);

  if (success) {
    return {
      address,
      txHash,
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
    }
  }
});

async function main() {
  try {
    await fastify.listen({ port: 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

process.on('SIGINT', () => fastify.close().then(() => process.exit(1)));

main();
