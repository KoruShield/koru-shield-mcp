FROM node:22-alpine

WORKDIR /app

# Install production dependencies only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy the prebuilt app
COPY dist/ ./dist/

ENV MCP_TRANSPORT=http
ENV PORT=3000

EXPOSE 3000

CMD ["node", "dist/index.js"]
