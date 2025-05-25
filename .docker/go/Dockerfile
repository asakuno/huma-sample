FROM golang:1.24.1-alpine

WORKDIR /app

RUN apk add --no-cache git
RUN go install github.com/air-verse/air@latest

COPY . .

RUN go mod tidy

CMD ["air"]