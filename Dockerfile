FROM node:12-alpine3.9

WORKDIR /usr/src/mockpass

COPY package* ./

RUN npm ci

COPY . ./

CMD ["node", "index.js"]
