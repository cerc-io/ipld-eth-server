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

fastify.get('/v1/deployContract', async (req, reply) => {
    const GLDToken = await hre.ethers.getContractFactory("GLDToken");
    const token = await GLDToken.deploy();
    await token.deployed();

    return {
        address: token.address,
        txHash: token.deployTransaction.hash,
        blockNumber: token.deployTransaction.blockNumber,
        blockHash: token.deployTransaction.blockHash,
    }
});

fastify.get('/v1/destroyContract', async (req, reply) => {
    const addr = req.query.addr;

    const Token = await hre.ethers.getContractFactory("GLDToken");
    const token = await Token.attach(addr);

    await token.destroy();
    const blockNum = await hre.ethers.provider.getBlockNumber()

    return {
        blockNumber: blockNum,
    }
})

fastify.get('/v1/sendEth', async (req, reply) => {
    const to = req.query.to;
    const value = req.query.value;

    const [owner] = await hre.ethers.getSigners();
    const tx = await owner.sendTransaction({
        to,
        value: hre.ethers.utils.parseEther(value)
    });
    await tx.wait(1)

    // console.log(tx);
    // const coinbaseBalance = await hre.ethers.provider.getBalance(owner.address);
    // const receiverBalance = await hre.ethers.provider.getBalance(to);
    // console.log(coinbaseBalance.toString(), receiverBalance.toString());

    return {
        from: tx.from,
        to: tx.to,
        //value: tx.value.toString(),
        txHash: tx.hash,
        blockNumber: tx.blockNumber,
        blockHash: tx.blockHash,
    }
});

fastify.get('/v1/deploySLVContract', async (req, reply) => {
    const SLVToken = await hre.ethers.getContractFactory("SLVToken");
    const token = await SLVToken.deploy();
    const receipt = await token.deployTransaction.wait();

    return {
        address: token.address,
        txHash: token.deployTransaction.hash,
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash,
    }
});

fastify.get('/v1/destroySLVContract', async (req, reply) => {
    const addr = req.query.addr;

    const SLVToken = await hre.ethers.getContractFactory("SLVToken");
    const token = SLVToken.attach(addr);

    const tx = await token.destroy();
    const receipt = await tx.wait();

    return {
        blockNumber: receipt.blockNumber,
    }
})

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
        await deployCreate2Factory(provider, signer)
    }

    const contractFactory = await hre.ethers.getContractFactory(contract);
    const bytecode = contractFactory.bytecode;
    const constructorTypes = [];
    const constructorArgs = [];

    const { txHash, address, receipt } = await deployContract({
        salt,
        contractBytecode: bytecode,
        constructorTypes: constructorTypes,
        constructorArgs: constructorArgs,
        signer
    });

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
        await fastify.listen(3000, '0.0.0.0');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
}

main();
