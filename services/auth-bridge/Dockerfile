FROM node:20

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY . .

CMD ["node", "server.js"]