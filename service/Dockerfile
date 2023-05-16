FROM golang:1.20-bullseye as base

# Create a seperate user and chown new directories if necessary
RUN addgroup --system service
RUN adduser --system --ingroup service --uid 1000 service

# Create our mapped data volume endpoint
RUN mkdir /data/

# Copy our entrypoint.sh and make it executable
COPY core-entrypoint.sh /
COPY ue-entrypoint.sh /
RUN chmod +x /core-entrypoint.sh
RUN chmod +x /ue-entrypoint.sh

# Copy our service
COPY src/ /service/

# Change the working directory.
WORKDIR /service/

RUN go mod download
RUN go mod verify

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /service/core cmd/core/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /service/ue cmd/ue/main.go

# Expose the service's port
EXPOSE 3399

# Run the service
# ENTRYPOINT ["/entrypoint.sh"]
