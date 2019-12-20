FROM node:12-alpine3.9

RUN apk update && apk upgrade

WORKDIR /usr/src/mockpass

COPY package* /usr/src/mockpass/

RUN npm ci

COPY . /usr/src/mockpass

CMD ["node", "index.js"]
