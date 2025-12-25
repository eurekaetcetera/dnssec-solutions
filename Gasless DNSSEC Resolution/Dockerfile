FROM node:20-slim

WORKDIR /app

# Install dependencies if package-lock.json is present
COPY package*.json ./ 
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; fi

# Copy source
COPY . .

EXPOSE 8787

CMD ["node", "server.mjs"]






