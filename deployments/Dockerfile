# Stage 1: Build - Dùng phiên bản Go ổn định
FROM golang:1.24-alpine AS builder

# Cài các công cụ cần thiết
RUN apk add --no-cache git build-base

WORKDIR /app

# Copy go.mod và go.sum, sau đó download dependencies
# Tận dụng Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy toàn bộ code source
COPY . .

# Build a static binary để không phụ thuộc C libraries trên alpine
# Thêm -ldflags "-w -s" để giảm kích thước binary
RUN CGO_ENABLED=0 go build -a -ldflags "-w -s" -o user-grpc-app ./cmd/server

# Stage 2: Runtime - Dùng image tối giản
FROM alpine:3.19

WORKDIR /app

# 🔹 TỐI ƯU BẢO MẬT: Tạo một user không có quyền root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy binary đã build từ stage builder
COPY --from=builder /app/user-grpc-app .

# 🔹 TỐI ƯU BẢO MẬT: Xóa dòng `COPY .env .`
# Cấu hình sẽ được truyền qua environment variables của Docker Compose

# Cấp quyền cho user mới
RUN chown -R appuser:appgroup /app
USER appuser

# Expose các cổng cần thiết
EXPOSE 50051 8080 6060

# Lệnh để chạy ứng dụng
CMD ["./user-grpc-app"]