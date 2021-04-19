const fastify = require('fastify')({ logger: true });
const hre = require("hardhat");

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

// fastify.get('/v1/deployContract', async (req, reply) => {
//     const GLDToken = await hre.ethers.getContractFactory("GLDToken");
//     const token = await GLDToken.deploy();
//     await token.deployed();
//     console.log("GLDToken deployed to:", token.address, token.deployTransaction);
//
//     return {
//         address: token.address,
//         txHash: token.deployTransaction.hash,
//         blockNumber: token.deployTransaction.blockNumber,
//     }
// });

async function main() {
    try {
        await fastify.listen(3000, '0.0.0.0');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
}

main();