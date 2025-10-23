FROM node:24-slim

WORKDIR /usr/src/mockpass

COPY package* ./

COPY ./.husky ./.husky

RUN npm ci

COPY . ./

CMD ["node", "index.js"]
