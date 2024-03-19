FROM node:16

WORKDIR /deposit-verify

COPY . .

WORKDIR /deposit-verify/utils/deposit_verify

RUN npm i

CMD [ "npm", "start" ]