FROM docker.io/library/node:18-alpine
MAINTAINER Jared Grippe jared@jlinc.com

# Install pnpm
RUN wget -qO /bin/pnpm "https://github.com/pnpm/pnpm/releases/download/v7.26.0/pnpm-linuxstatic-x64" && chmod +x /bin/pnpm

RUN mkdir -p /app
WORKDIR /app

# install node modules
COPY package.json ./package.json
COPY pnpm-lock.yaml ./pnpm-lock.yaml
RUN pnpm install

# copy over latest app
COPY . .
RUN pnpm install

ENV PORT=80
EXPOSE 80
CMD env && pnpm run start
