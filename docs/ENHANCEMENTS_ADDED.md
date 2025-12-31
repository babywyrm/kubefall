# Enhancements Added to kubefall

Based on comprehensive Kubernetes pentest research, we've added several critical features to make kubefall more comprehensive and practical for both red and blue teams.

## ✅ Completed Enhancements (Latest Update)

### 1. **Pod Security Context Analysis** (`internal/analysis/pods.go`)
**Priority: CRITICAL**

Automatically analyzes pod configurations for dangerous security settings:
- **Privileged pods** - Can escape container boundaries
- **HostNetwork pods** - Share host network namespace
- **HostPID pods** - Can see host processes
- **HostPath mounts** - Dangerous filesystem mounts (/, /var/lib/kubelet, etc.)
- **Dangerous capabilities** - SYS_ADMIN, NET_ADMIN, SYS_PTRACE, etc.
- **RunAsRoot** - Pods running as root (UID 0)
- **AllowPrivilegeEscalation** - Can escalate privileges

**Usage:** Automatically runs when `--dump` is used and you have pod read permissions.

### 2. **Cluster Information Discovery** (`internal/discovery/cluster.go`)
**Priority: HIGH**

Discovers cluster metadata:
- **Cluster version** - Kubernetes version (for CVE hunting)
- **Node information** - Kubelet version, OS image, architecture, container runtime

**Usage:** Automatically runs on every execution.

### 3. **Enhanced RBAC Analysis** (`internal/analysis/rbac.go`)
**Priority: HIGH**

Deep analysis of RBAC configurations:
- **Cluster-admin bindings** - Finds all subjects bound to cluster-admin or admin roles
- **Wildcard roles** - Identifies roles with wildcard permissions
- **Secret access roles** - Roles that can read secrets
- **Pod creation roles** - Roles that can create pods

**Usage:** Automatically runs when clusterrolebindings are readable.

### 4. **Service Account Token Extraction** (`internal/analysis/tokens.go`)
**Priority: HIGH**

Automatically extracts and validates ServiceAccount tokens:
- **Token Discovery**: Finds SA tokens in secrets (type: `kubernetes.io/service-account-token`)
- **Token Validation**: Decodes JWT claims and validates tokens
- **High-Privilege SA Detection**: Identifies ServiceAccounts with potentially elevated privileges
- **SA Enumeration**: Lists all ServiceAccounts from pods and ServiceAccount resources

**Usage:** Automatically runs when `--dump` is used and you have secret/pod/serviceaccount read permissions.

### 5. **Enhanced Output Display & Export**
**Priority: HIGH**

**New Output Formats:**
- **CSV Export** - For spreadsheet analysis (`--format csv`)
- **HTML Reports** - Visual reports with tables (`--format html`)
- **Markdown** - Documentation-friendly format (`--format markdown`)
- **File Export** - Write to file (`--output filename`)

**Filtering & Display Options:**
- **Severity Filtering** - Show only specific severities (`--severity critical,high`)
- **Summary Only** - Condensed output (`--summary-only`)
- **No Color** - Script-friendly output (`--no-color`)

**Separated Severity Sections:**
- 🔴 **CRITICAL FINDINGS** - Separate red banner section
- 🟠 **HIGH SEVERITY FINDINGS** - Separate yellow banner section
- 🟡 **INTERESTING FINDINGS** - Yellow section
- 🟢 **NORMAL** - Standard permissions

This separation allows for future extensibility (medium, low, info levels).

## 📋 What's Next (Future Phases)

### Phase 4: Advanced Enumeration (Next Priorities)
1. **Dynamic API Discovery** - Automatically discover CRDs and custom resources
2. **Event Enumeration** - Recent security events and failed auth attempts
3. **Network Policy Analysis** - Identify missing network segmentation
4. **Ingress TLS Analysis** - Certificate and routing configuration
5. **Persistent Volume Analysis** - Storage configuration and access modes

### Phase 5: Attack Path Analysis
1. **Capability Mapping** - Map permissions to actual attack capabilities
2. **Attack Path Generation** - Generate attack paths with confidence scoring
3. **Token Reuse Detection** - Test discovered tokens for different permissions
4. **ServiceAccount Impersonation Testing** - Test impersonation capabilities

### Phase 6: Detection & Compliance
1. **MITRE ATT&CK Mapping** - Map findings to attack techniques
2. **Falco Rule Generation** - Generate detection rules based on findings
3. **Compliance Checks** - CIS, NSA, and other compliance frameworks
4. **Baseline Comparison** - Compare against known-good configurations

## 🔧 Technical Implementation

### New Modules
- `internal/analysis/pods.go` - Pod security analysis
- `internal/analysis/rbac.go` - RBAC analysis  
- `internal/discovery/cluster.go` - Cluster discovery
- `internal/output/formatter_additions.go` - Enhanced output display

### Integration Points
- Pod security analysis runs automatically when `--dump` is used
- RBAC analysis runs when clusterrolebindings are readable
- Cluster info discovery runs on every execution
- All findings are integrated into the existing output format

## 📊 Example Output

When you run `kubeenum --dump`, you'll now see:

```
╔════════════════════════════════════════════════════════════╗
║  🔒 POD SECURITY ANALYSIS                                  ║
╚════════════════════════════════════════════════════════════╝

  [kube-system] 🚨 PRIVILEGED PODS:
    • privileged-pod-123 (SA: default)

  [kube-system] 🌐 HOST NETWORK PODS:
    • host-network-pod-456

  [kube-system] 📁 DANGEROUS HOST PATH MOUNTS:
    • pod-with-mount -> /var/lib/kubelet (read-only)

╔════════════════════════════════════════════════════════════╗
║  🔴 CLUSTER-ADMIN BINDINGS FOUND 🔴                        ║
╚════════════════════════════════════════════════════════════╝

  Binding: system:admin
  Role:    cluster-admin
  Subjects:
    • ServiceAccount: admin-sa (ns: default)
```

## 🎯 Usage

```bash
# Basic enumeration (includes cluster info)
./kubeenum

# Full enumeration with pod security analysis
./kubeenum --dump

# Full enumeration with complete data display
./kubeenum --dump --full

# Export only critical/high findings to CSV
./kubeenum --dump --severity critical,high --format csv --output critical.csv

# Generate HTML report
./kubeenum --dump --format html --output report.html

# Summary only (condensed)
./kubeenum --summary-only

# JSON output for automation
./kubeenum --dump --format json --output results.json
```

## 🔍 Detection Coverage

The tool now checks for:
- ✅ Privileged containers
- ✅ Host network/PID namespace sharing
- ✅ Dangerous hostPath mounts
- ✅ Dangerous capabilities
- ✅ Cluster-admin bindings
- ✅ Wildcard RBAC permissions
- ✅ Cluster version (CVE hunting)
- ✅ Node information
- ✅ ServiceAccount tokens in secrets
- ✅ High-privilege ServiceAccounts
- ✅ Extracted credentials and tokens
- ✅ Network services and exposure

All findings are automatically prioritized and displayed with actionable information for both attackers and defenders.

## 📊 Output Formats

The tool supports multiple output formats for different use cases:

- **Text** (default): Human-readable, color-coded output
- **JSON**: Machine-readable for automation and integration
- **CSV**: Spreadsheet-friendly for analysis and filtering
- **HTML**: Visual reports with tables and styling
- **Markdown**: Documentation-friendly format

## 🎛️ Filtering Options

- **Severity Filtering**: Focus on specific severity levels
  - `--severity critical` - Only critical findings
  - `--severity critical,high` - Critical and high findings
  - `--severity interesting` - Only interesting findings

- **Summary Mode**: Quick overview without detailed sections
  - `--summary-only` - Just the summary section

- **File Export**: Save results for later analysis
  - `--output filename` - Write to file instead of stdout

- **No Color**: For scripts and logs
  - `--no-color` - Disable ANSI color codes

