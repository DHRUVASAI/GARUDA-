#!/usr/bin/env bash
set -euo pipefail

# Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in your shell before running:
#   export AWS_ACCESS_KEY_ID="YOUR_ROTATED_KEY"
#   export AWS_SECRET_ACCESS_KEY="YOUR_ROTATED_SECRET"
#   export AWS_DEFAULT_REGION="us-east-1"

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
KEY_NAME="${GARUDA_KEY_NAME:-garuda-v7-key}"
SG_NAME="${GARUDA_SG_NAME:-garuda-v7-sg}"
INSTANCE_TYPE="${GARUDA_INSTANCE_TYPE:-t3.small}"

echo "[1/4] Creating Security Group ($SG_NAME) in $REGION..."
SG_ID=$(aws ec2 create-security-group   --region "$REGION"   --group-name "$SG_NAME"   --description "GARUDA v7 Production Security Group"   --query 'GroupId' --output text 2>/dev/null ||   aws ec2 describe-security-groups --region "$REGION" --group-names "$SG_NAME" --query 'SecurityGroups[0].GroupId' --output text)

for PORT in 22 80 443 8000; do
  aws ec2 authorize-security-group-ingress --region "$REGION"     --group-id "$SG_ID" --protocol tcp --port "$PORT" --cidr 0.0.0.0/0 2>/dev/null || true
done

echo "[2/4] Ensuring SSH Key Pair ($KEY_NAME)..."
if [ ! -f "${KEY_NAME}.pem" ]; then
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME"     --query 'KeyMaterial' --output text > "${KEY_NAME}.pem"
  chmod 400 "${KEY_NAME}.pem"
fi

echo "[3/4] Finding latest Ubuntu 24.04 LTS AMI..."
AMI_ID=$(aws ec2 describe-images --region "$REGION" --owners 099720109477   --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"   --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)

echo "[4/4] Launching EC2 instance ($INSTANCE_TYPE)..."
USER_DATA=$(cat <<'EOF'
#!/bin/bash
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y docker.io docker-compose-v2 nginx
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y docker nginx
elif command -v yum >/dev/null 2>&1; then
  yum install -y docker nginx
fi
systemctl enable --now docker
usermod -aG docker ubuntu 2>/dev/null || usermod -aG docker ec2-user 2>/dev/null || true
EOF
)

INSTANCE_ID=$(aws ec2 run-instances   --region "$REGION"   --image-id "$AMI_ID"   --count 1   --instance-type "$INSTANCE_TYPE"   --key-name "$KEY_NAME"   --security-group-ids "$SG_ID"   --user-data "$USER_DATA"   --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=garuda-v7-prod}]'   --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
PUBLIC_IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID"   --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "============================================================"
echo "GARUDA v7 EC2 Instance Ready!"
echo "Instance ID : $INSTANCE_ID"
echo "Public IP   : $PUBLIC_IP"
echo "Next steps  :"
echo "  scp -i ${KEY_NAME}.pem -r . ubuntu@${PUBLIC_IP}:~/garuda-v7"
echo "  ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP}"
echo "  cd ~/garuda-v7 && cp .env.example .env && nano .env && docker compose up -d --build"
echo "============================================================"
