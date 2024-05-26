FROM node:slim

WORKDIR /usr/src/mockpass

COPY package* ./

COPY ./.husky ./.husky

RUN npm ci

COPY . ./

CMD ["node", "index.js"]
