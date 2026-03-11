# Bootstrap Bundle

The files in this directory are bundled into a **self-extracting script** (we
call this be-BOP bootstrap). When executed, that script unpacks this directory
into a temporary location and then launches **be-bop-wizard**, which performs
the actual installation and initial configuration of be-BOP. Because this is a
drop-in replacement for the wizard, the resulting artifact is named
`be-bop-wizard.sh`.

This folder exists in two contexts:

## If you are viewing this inside source control

This directory defines the **exact payload** that will be embedded into the
script. Everything placed here is shipped to users and will appear exactly as-is
when the bootstrap script extracts itself.

Typical contents include:

- [be-bop-wizard.sh](#be-bop-wizard) — the interactive installer responsible for
  deployment.
- [be-bop-cli.sh](#be-bop-cli) — the CLI used during setup and by operators
  after installation.
- Optional assets (templates, defaults, helper scripts).

Only purposeful, version-controlled files should live here. \
Do **not** place temporary files, build outputs, or experiment artifacts.

## If you found this directory in `/tmp` (or another temp location)

You likely just ran the **be-BOP bootstrap** installer.

This directory is the unpacked installation payload that the bootstrapper uses
internally. It is safe to inspect, and normally it will be cleaned up
automatically after the installation completes.

It contains the scripts and tools that the installer used to configure your
system. You can usually delete it unless debugging an installation issue.

---

# be-bop-wizard

This is a self-guided installation and configuration tool for be-BOP.
It’s not a traditional “fire-and-pray” installer — it actually looks at your
system first, figures out what’s missing, and only does what’s needed. You can
think of it as a checklist manager for system setup.

## 💡 What It Does

- Inspects your system to see what’s already installed and running.
- Plans what steps are needed to bring the environment to a working BeBop setup.
- Prepares any missing tools (like curl, jq, or systemctl).
- Executes the setup tasks in the correct order.
- Summarizes what it did, what’s running, and where to look if something failed.

It can be safely rerun — it’s designed to resume where it left off without
breaking anything that already works.

## Usage

### 🚀 Quick Start

```bash
be-bop-wizard.sh --domain example.com --email admin@example.com
```

### Command-line Options

See `be-bop-wizard.sh --help` for a list of available options.

### Examples

**Interactive installation:**
```bash
be-bop-wizard.sh --domain mybebop.com --email admin@mybebop.com
```

**Non-interactive installation (for automation):**
```bash
be-bop-wizard.sh \
  --domain mybebop.com \
  --email admin@mybebop.com \
  --non-interactive
```

**Localhost development setup:**
```bash
be-bop-wizard.sh --domain localhost --email dev@localhost
```

**Use releases from your custom fork:**
```bash
export BEBOP_GITHUB_REPO="your-username/be-BOP"
be-bop-wizard.sh --domain example.com --email admin@example.com
```

## System Requirements

### Supported Operating Systems

- **Debian 12** (bookworm)
- **Ubuntu 24.04** LTS (noble)
- **Ubuntu 22.04** LTS (jammy)
- **Ubuntu 20.04** LTS (focal)

### System Prerequisites

- User with sudo privileges (or root with `--allow-root`)
- Internet connectivity
- At least 1GB RAM (recommended 2GB)
- At least 10GB disk space

### Network Requirements

For production deployments (non-localhost):
- Domain name with A/AAAA records pointing to the server
- Ports 80 and 443 accessible from the internet (for Let's Encrypt)
- DNS resolution for both `example.com` and `s3.example.com`

## 🛠️ What It Installs and Configures

be-bop-wizard handles:

- Node.js and pnpm (for running be-BOP)
- MongoDB (database backend)
- MinIO (object storage service)
- Nginx (reverse proxy and HTTPS endpoint)
- Certbot (Let’s Encrypt SSL certificate provisioning)
- be-BOP itself — the latest stable release from GitHub

🔒 Security Notes

- Services are installed with strict systemd sandboxing (read-only system,
  private /tmp, no device access, etc.).
- Package repositories are added with GPG key verification.
- SSL certificates are provisioned via Let’s Encrypt automatically.

## Architecture

`be-bop-wizard` follows the **bootstrap-then-delegate** pattern:

```
be-bop-wizard (bootstrap)
    ├── Environment detection
    ├── Smart dependency analysis
    ├── System provisioning
    │   ├── Node.js + pnpm
    │   ├── MongoDB (with replica set)
    │   ├── nginx + SSL
    │   ├── phoenixd (Lightning Network)
    │   └── MinIO (Object Storage)
    ├── Application deployment
    └── Delegation to be-bop-cli (future)
```

### 🧩 How It Works (in plain English)

be-bop-wizard isn’t just a pile of shell commands. It behaves more like a mini
automation engine:

- It collects facts about your system — e.g., “MongoDB is running,” “Nginx is
  not installed.”
- From those facts, it decides what tasks to perform.
- Each task lists which tools it needs and what it changes.
- It executes those tasks in a controlled sequence, ensuring prerequisites are
  met.

Under the hood, it quietly borrows ideas from:

- Expert systems — rule-based reasoning (“if X is missing, do Y”)
- Effect systems — describing what operations can safely change the system
- Interpreters — reading a list of actions and executing them in order

Yes, it’s all written in Bash — a 1970s language running modern ideas.
A little bit of logic theory wrapped in duct tape and wizardry.

## Configuration Files

The wizard creates these configuration files using `ucf` for proper management:

### Repository Configuration
- `/etc/apt/sources.list.d/nodesource.list` - Node.js repository
- `/etc/apt/preferences.d/nodejs` - Node.js package preferences
- `/etc/apt/sources.list.d/mongodb-org-8.0.list` - MongoDB repository
- `/usr/share/keyrings/nodesource.gpg` - Node.js repository GPG key
- `/usr/share/keyrings/mongodb-server-8.0.gpg` - MongoDB repository GPG key

### Service Configuration
- `/etc/nginx/sites-available/be-BOP.conf` - nginx reverse proxy configuration
- `/etc/minio/config.env` - MinIO credentials and settings
- `/etc/be-BOP/config.env` - be-BOP application environment

### Systemd Services
- `/etc/systemd/system/phoenixd.service` - phoenixd Lightning daemon
- `/etc/systemd/system/minio.service` - MinIO object storage
- `/etc/systemd/system/bebop.service` - be-BOP application server

### Security Hardening (VM/bare metal only)
- `/etc/systemd/system/phoenixd.service.d/overrides.conf`
- `/etc/systemd/system/minio.service.d/overrides.conf`
- `/etc/systemd/system/bebop.service.d/overrides.conf`

## Logging

Logs are written to:
- **stdout/stderr**: User-facing messages with progress indicators
- **journald**: System logging (if available)
- **Session ID**: Each run gets a unique identifier for correlation

View logs:
```bash
# View wizard logs
sudo journalctl -t be-bop-wizard

# View all be-BOP stack logs
sudo journalctl -t be-bop-wizard -t bebop -t phoenixd -t minio

# View specific service logs
sudo journalctl -u bebop -f
sudo journalctl -u phoenixd -f
sudo journalctl -u minio -f
```

---

# be-bop-cli

Simple CLI tool to perform regular maintenance operations in a be-BOP
installation.

This tool in installed by be-bop-wizard.

## Usage

### 🚀 Quick Start

See `be-bop-wizard.sh --help` for a list of available options.
