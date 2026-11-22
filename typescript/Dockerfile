FROM node:22-alpine
WORKDIR /app
COPY package.json tsconfig.json ./
COPY src ./src
EXPOSE 8081
CMD ["node", "--experimental-strip-types", "src/index.ts"]
