# Downgrade from 18.16, see https://github.com/NomicFoundation/hardhat/issues/3877
FROM node:18.15-slim

ARG ETH_ADDR
ENV ETH_ADDR $ETH_ADDR

WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run compile && ls -lah

EXPOSE 3000

ENTRYPOINT ["node", "src/index.js"]
