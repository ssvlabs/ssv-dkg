FROM node:16@sha256:f77a1aef2da8d83e45ec990f45df50f1a286c5fe8bbfb8c6e4246c6389705c0b

WORKDIR /deposit-verify

COPY . .

WORKDIR /deposit-verify/utils/deposit_verify

RUN npm i

CMD [ "npm", "start" ]