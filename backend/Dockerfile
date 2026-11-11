FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY app.js server.js ./
USER node
EXPOSE 8000
CMD ["npm","start"]
