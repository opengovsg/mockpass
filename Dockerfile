FROM node:12-alpine3.9

WORKDIR /usr/src/mockpass

COPY package* /usr/src/mockpass/

RUN npm ci

COPY . /usr/src/mockpass

CMD ["node", "index.js"]
