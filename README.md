# SecureFlow AI — AI-Augmented DevSecOps Pipeline

> Every code push triggers four parallel security scans. All findings feed into an AI triage engine (Claude or Gemini) that deduplicates noise, prioritizes by real-world exploitability, and posts a structured report as a PR comment. A configurable security gate blocks the build if thresholds are exceeded.

---

## Architecture

```
Code Push / PR
      │
      ▼
┌─────────────────────────────────────────────┐
│           GitHub Actions Pipeline            │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   SAST   │  │   SCA    │  │ Secrets  │  │
│  │ Semgrep  │  │  Trivy   │  │Gitleaks  │  │
│  │SonarQube │  │          │  │          │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │        │
│  ┌────┴──────────────┴──────────────┴─────┐  │
│  │         Container + IaC Scan           │  │
│  │      Trivy · Checkov · Hadolint        │  │
│  └────────────────────┬───────────────────┘  │
│                       │                      │
│              ┌────────▼────────┐             │
│              │   AI Triage     │             │
│              │ Claude / Gemini │             │
│              └────────┬────────┘             │
│                       │                      │
│              ┌────────▼────────┐             │
│              │ Security Gate   │             │
│              │  PASS / FAIL    │             │
│              └────────┬────────┘             │
└───────────────────────┼─────────────────────┘
                        │
               ┌────────▼────────┐
               │  Deploy to K8s  │
               │   (minikube)    │
               └─────────────────┘
                        │
               ┌────────▼────────┐
               │ Runtime Monitor │
               │     Falco       │
               └─────────────────┘
```

## Tools

| Stage | Tool | Purpose |
|-------|------|---------|
| SAST | Semgrep, SonarQube | Source code vulnerability analysis |
| SCA | Trivy | Dependency CVE scanning |
| Secrets | Gitleaks | Hardcoded credential detection |
| Container/IaC | Trivy, Checkov, Hadolint | Image + Terraform misconfiguration |
| SBOM | Syft | Software bill of materials |
| AI Triage | Claude API / Gemini API | Dedup, prioritize, remediate findings |
| Runtime | Falco | Container threat detection |
| Monitoring | Prometheus + Grafana | Security posture dashboard |

---

## Prerequisites

### All platforms

- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/products/docker-desktop/) (Desktop recommended)
- [minikube](https://minikube.sigs.k8s.io/docs/start/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Helm](https://helm.sh/docs/intro/install/)
- Python 3.9+
- A Gemini API key from [aistudio.google.com/apikey](https://aistudio.google.com/apikey) (free) or Claude API key from [console.anthropic.com](https://console.anthropic.com)

---

## GitHub Actions Configuration

**1. Add secrets** — repo → Settings → Secrets and variables → Actions:

| Secret | Value |
|--------|-------|
| `GEMINI_API_KEY` | From [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| `ANTHROPIC_API_KEY` | From [console.anthropic.com](https://console.anthropic.com) (optional) |
| `SONAR_TOKEN` | From your SonarQube project settings (optional) |
| `SONAR_HOST_URL` | Your SonarQube URL (optional) |

**2. Add variable** — Settings → Variables → Actions:

| Variable | Value |
|----------|-------|
| `AI_PROVIDER` | `gemini` or `claude` |

**3. Push to trigger the pipeline**
```bash
git add .
git commit -m "feat: trigger secureflow pipeline"
git push origin main
```

**4. Test PR comments**
```bash
git checkout -b feature/test-scan
echo "# test" >> README.md
git add . && git commit -m "test: trigger AI triage"
git push origin feature/test-scan
# Open a PR on GitHub — AI report posts as a comment
```

---

## Setup

### Windows (WSL2)

> All commands run inside WSL2 (Ubuntu). Install it first if needed.

**1. Enable WSL2 + Ubuntu**
```powershell
# Run in PowerShell as Administrator
wsl --install
wsl --set-default-version 2
# Restart, then install Ubuntu from Microsoft Store
```

**2. Enable Docker Desktop WSL integration**

Open Docker Desktop → Settings → Resources → WSL Integration → enable Ubuntu → Apply & Restart.

**3. Install tools inside WSL**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip python3-venv -y

# Semgrep
pip3 install semgrep

# Trivy
sudo apt install wget apt-transport-https gnupg -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install trivy -ycd ~/secureflow-ai


# Gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_8.18.4_linux_x64.tar.gz && sudo mv gitleaks /usr/local/bin/

# Checkov
pip3 install checkov

# Hadolint
wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64
sudo chmod +x /usr/local/bin/hadolint

# Syft (SBOM)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Python SDKs
pip3 install anthropic requests

# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

> **Port forwarding note:** Docker containers run inside WSL2's network. To access them from your Windows browser, run this in PowerShell as Administrator after starting containers:
> ```powershell
> $wslIp = (wsl hostname -I).Trim().Split(" ")[0]
> netsh interface portproxy add v4tov4 listenport=3000 listenaddress=127.0.0.1 connectport=3000 connectaddress=$wslIp
> netsh interface portproxy add v4tov4 listenport=9090 listenaddress=127.0.0.1 connectport=9090 connectaddress=$wslIp
> ```
> Or enable mirrored networking in `%USERPROFILE%\.wslconfig`:
> ```ini
> [wsl2]
> networkingMode=mirrored
> ```

---

### macOS

```bash
# Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Tools
brew install python semgrep trivy gitleaks hadolint helm kubectl minikube

# Checkov + Syft + Python SDKs
pip3 install checkov anthropic requests
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Docker Desktop
brew install --cask docker
```

---

### Linux (Ubuntu/Debian)

Same as the WSL2 commands above, run natively in your terminal. No port forwarding needed — `localhost` works directly.

---

## Running locally

**1. Clone the repo**
```bash
git clone https://github.com/vikassharma-3/secureflow-ai.git
cd secureflow-ai
```

**2. Start minikube**
```bash
minikube start --driver=docker
```

**3. Build and deploy the app**
```bash
eval $(minikube docker-env)
docker build -t secureflow-app:latest ./app
kubectl apply -f kubernetes/
kubectl get pods   # wait for Running
minikube service secureflow-app-svc --url
```

**4. Start monitoring stack**
```bash
# Create prometheus config directory
mkdir -p monitoring/prometheus-config
cat > monitoring/prometheus-config/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]
EOF

cd monitoring
docker compose up -d
```

Access Grafana at `http://localhost:3000` — login: `admin` / `secureflow123`

In Grafana: Connections → Data sources → Prometheus → set URL to `http://prometheus:9090` → Save & test.

**5. Run security scans locally**
```bash
cd ~/secureflow-ai   # or wherever you cloned

# Run all scanners
semgrep --config=p/owasp-top-ten --json --output=semgrep.json app/ || true
trivy fs --severity CRITICAL,HIGH --format json --output trivy-fs.json . || true
gitleaks detect --source . --report-format json --report-path gitleaks.json --exit-code 0 || true
checkov -d infrastructure --output json 2>/dev/null > checkov.json || true
hadolint app/Dockerfile --format json > hadolint.json || true
syft app/ -o cyclonedx-json=sbom.json

# Organize results
mkdir -p sast-results sca-results secrets-results container-iac-results
cp semgrep.json sast-results/
cp trivy-fs.json sca-results/
cp gitleaks.json secrets-results/
cp hadolint.json checkov.json container-iac-results/

# Run AI triage (pick one)
GEMINI_API_KEY="your_key" python3 scripts/ai_triage.py
# or
ANTHROPIC_API_KEY="your_key" AI_PROVIDER=claude python3 scripts/ai_triage.py

# View report
cat triage_report.md

# Run security gate
python3 scripts/security_gate.py
```

**6. Install Falco (Linux / macOS only)**

> Falco requires a native Linux kernel for full syscall monitoring. On WSL2, it installs successfully but syscall interception is limited due to Microsoft's kernel restrictions.

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true

kubectl get pods -n falco -w
```

---

## Known limitations

| Limitation | Detail |
|------------|--------|
| **Falco on WSL2** | Microsoft's WSL2 kernel restricts eBPF program loading. Falco installs and loads rules correctly but cannot intercept syscalls. Use a native Linux VM or cloud instance (EC2, GKE) for full runtime monitoring. |
| **Docker port forwarding on WSL2** | Containers bind to WSL2's network interface, not Windows localhost. Use the portproxy commands above or enable `networkingMode=mirrored` in `.wslconfig`. |
| **Checkov output** | Running `checkov` locally with `--output-file-path` creates a directory instead of a file. Use `checkov -d infrastructure --output json > checkov.json` instead. |

---

## Project structure

```
secureflow-ai/
├── .github/
│   └── workflows/
│       └── devsecops.yml        ← GitHub Actions pipeline
├── app/
│   ├── app.py                   ← intentionally vulnerable Flask app
│   ├── requirements.txt
│   └── Dockerfile
├── infrastructure/
│   └── main.tf                  ← Terraform with intentional Checkov findings
├── kubernetes/
│   ├── deployment.yaml
│   └── service.yaml
├── scripts/
│   ├── ai_triage.py             ← Claude / Gemini triage engine
│   └── security_gate.py        ← pass/fail enforcement
├── monitoring/
│   ├── docker-compose.yaml
│   └── prometheus-config/
│       └── prometheus.yml
└── README.md
```

---

## Quick reference

```bash
# Start everything
minikube start --driver=docker
cd monitoring && docker compose up -d

# Watch pipeline logs
kubectl logs -l app.kubernetes.io/name=falco -n falco -f

# Access services
# Grafana:    http://localhost:3000  (admin / secureflow123)
# Prometheus: http://localhost:9090
# App:        $(minikube service secureflow-app-svc --url)/health
```
