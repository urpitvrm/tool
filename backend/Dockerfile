FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY app.js server.js ./
# Persistent report storage; mount a volume here (see docker-compose.yml).
RUN mkdir -p /app/storage/reports && chown -R node:node /app/storage
ENV REPORT_STORAGE_DIR=/app/storage/reports
USER node
EXPOSE 8000
CMD ["npm","start"]
