const fastify = require('fastify')({ logger: true });
const hre = require("hardhat");
const { getStorageSlotKey } = require('./utils');


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

async function main() {
    try {
        await fastify.listen(3000, '0.0.0.0');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
}

main();