# syntax=docker/dockerfile:1
FROM node:latest AS build
WORKDIR /app
COPY . .
RUN npm ci

FROM node
ENV API_TOKEN=fake-api-token-not-real-0000000
ARG DB_PASSWORD=hunter2-not-a-real-pw
ADD https://example.com/install.sh /tmp/install.sh
RUN sh /tmp/install.sh \
    && rm /tmp/install.sh
COPY --from=build /app /app
CMD ["node", "server.js"]
