FROM node:16-alpine

WORKDIR /usr/src/mockpass

COPY package* ./
ENV SHOW_LOGIN_PAGE 'true'
RUN npm ci

COPY . ./

CMD ["node", "index.js"]
