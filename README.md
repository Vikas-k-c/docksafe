# DockSafe

DockSafe is a DevSecOps-based Docker image vulnerability scanner. It provides a web interface where users can enter a Docker image name and view vulnerability risk details, remediation suggestions, image metadata, and scan summaries.

This project demonstrates DevSecOps practices such as containerization, CI/CD automation, dependency auditing, Docker image scanning, and security-focused reporting.

## Features

- React frontend for Docker image scan input and result visualization
- Node.js/Express backend API
- Dockerized frontend and backend
- Docker Compose setup for local deployment
- GitHub Actions CI/CD pipeline
- Dependency audit using `npm audit`
- Docker image vulnerability scanning using Trivy
- Trivy scan reports uploaded as GitHub Actions artifacts
- Fast demo mode for quick classroom/project demonstrations
- Health check endpoint for backend service

## Tech Stack

- Frontend: React, Vite, Axios
- Backend: Node.js, Express
- Containerization: Docker, Docker Compose
- CI/CD: GitHub Actions
- Security Scanning: Trivy, npm audit
- Web Server: Nginx for frontend container

## Project Structure

```text
docksafe/
├── backend/
│   ├── server.js
│   ├── analyzer.js
│   ├── suggestions.js
│   ├── Dockerfile
│   ├── package.json
│   └── .env.example
├── frontend/
│   ├── src/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   └── index.html
├── .github/
│   └── workflows/
│       └── ci-cd.yml
├── docker-compose.yml
└── README.md
```

## How To Run Locally With Docker

Make sure Docker Desktop is running.

```powershell
cd C:\Users\vikas\OneDrive\Desktop\docksafe
docker compose up --build
```

Open the frontend:

```text
http://localhost:8080
```

Backend health check:

```text
http://localhost:5000/health
```

To stop the project:

```powershell
docker compose down
```

## Fast Demo Mode

By default, the project uses fast demo mode:

```yaml
FAST_SCAN_MODE: true
```

This returns simulated but realistic scan results in a few seconds. It is useful for presentations and classroom demos.

To use real Trivy scans, update `docker-compose.yml`:

```yaml
FAST_SCAN_MODE: false
```

Then rebuild:

```powershell
docker compose down
docker compose up --build
```

Real Trivy scans may take longer because Trivy downloads vulnerability databases and analyzes image layers.

## Backend API

### Health Check

```http
GET /health
```

Response:

```json
{
  "ok": true
}
```

### Scan Docker Image

```http
POST /scan
```

Request body:

```json
{
  "image": "alpine:latest"
}
```

Response includes:

- vulnerability counts
- risk score
- image size
- layer count
- remediation suggestions
- top vulnerability findings
- scan duration

## CI/CD Pipeline

The GitHub Actions workflow is located at:

```text
.github/workflows/ci-cd.yml
```

The pipeline runs automatically on push or pull request to `main` or `master`.

Pipeline stages:

```text
Frontend quality gate
Backend quality gate
Docker build and scan
```

### Frontend Quality Gate

- Installs dependencies
- Runs ESLint
- Builds frontend
- Runs dependency audit

### Backend Quality Gate

- Installs dependencies
- Runs dependency audit

### Docker Build And Scan

- Builds backend Docker image
- Builds frontend Docker image
- Scans images using Trivy
- Uploads Trivy reports as workflow artifacts

## DevSecOps Concepts Demonstrated

This project demonstrates:

- Continuous Integration
- Continuous Delivery pipeline structure
- Docker containerization
- Docker Compose orchestration
- Dependency vulnerability auditing
- Container image vulnerability scanning
- Security reports as CI artifacts
- Environment variable configuration
- Health checks
- Secure separation of frontend and backend services

## GitHub Actions Automation

After pushing code to GitHub, go to:

```text
Repository -> Actions -> CI/CD
```

The workflow will run automatically.

You can also trigger it manually:

```text
Actions -> CI/CD -> Run workflow
```

## Example Images To Scan

```text
alpine:latest
nginx:latest
node:20-alpine
python:3.9
redis:7
```

## Author

Vikas K C

## Project Purpose

This project was developed as a DevSecOps subject project to demonstrate how security can be integrated into the software development lifecycle using CI/CD, Docker, and automated vulnerability scanning.
