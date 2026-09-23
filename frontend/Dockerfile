FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

EXPOSE 5173

CMD ["sh", "-c", "if [ ! -x node_modules/.bin/vite ]; then npm ci; fi; exec npm run dev -- --host 0.0.0.0 --port 5173"]
