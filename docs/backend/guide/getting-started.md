# 快速开始

本指南将帮助你快速部署和运行 4zreark。

## 环境要求

- **Go**: 1.21+
- **Node.js**: 18+
- **MongoDB**: 5.0+
- **Redis**: 6.0+ (可选，推荐用于任务队列)
- **Docker & Docker Compose** (可选，用于容器化部署)

## 部署方式

### 方式一：Docker Compose 部署 (推荐)

1. **克隆仓库**
   ```bash
   git clone https://github.com/SantaVp3/Moon-Gazing-Tower.git
   cd 4zreark
   ```

2. **启动服务**
   进入 `backend` 目录并启动：
   ```bash
   cd backend
   docker-compose up -d
   ```
   这将自动启动 MongoDB, Redis 和后端服务。

3. **启动前端**
   ```bash
   cd ../frontend
   npm install
   npm run dev
   ```

### 方式二：手动部署

#### 1. 后端配置与启动

1. 进入后端目录：
   ```bash
   cd backend
   ```

2. 配置 `config/config.yaml`：
   确保 MongoDB 和 Redis 的连接信息正确。
   ```yaml
   mongodb:
     uri: mongodb://localhost:27017
     database: moongazing
   redis:
     addr: localhost:6379
   ```

3. 运行后端：
   ```bash
   go mod download
   go run main.go
   ```

#### 2. 前端启动

1. 进入前端目录：
   ```bash
   cd frontend
   ```

2. 安装依赖并运行：
   ```bash
   npm install
   npm run dev
   ```

## 访问系统

- **前端地址**: http://localhost:5173 (默认)
- **后端 API**: http://localhost:8080

### 首次初始化

系统不再内置默认账号。首次访问页面会自动跳转到「初始化管理员」页：

- 自行设定管理员用户名与密码（密码至少 8 位）
- 创建成功后直接进入系统，该初始化入口随之永久关闭

> ⚠️ **注意**: 初始化入口只在库里没有任何账号时可用；之后请通过登录页进入。
