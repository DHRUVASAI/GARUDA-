# Run in PowerShell after setting rotated AWS credentials:
#   $env:AWS_ACCESS_KEY_ID="YOUR_ROTATED_KEY"
#   $env:AWS_SECRET_ACCESS_KEY="YOUR_ROTATED_SECRET"
#   $env:AWS_DEFAULT_REGION="us-east-1"

$ErrorActionPreference = "Stop"
$Region = if ($env:AWS_DEFAULT_REGION) { $env:AWS_DEFAULT_REGION } else { "us-east-1" }
$KeyName = "garuda-v7-key"
$SgName = "garuda-v7-sg"
$InstanceType = "t3.small"

Write-Host "[1/4] Creating Security Group ($SgName) in $Region..."
$SgId = aws ec2 create-security-group --region $Region --group-name $SgName --description "GARUDA v7 Prod" --query "GroupId" --output text 2>$null
if (-not $SgId) {
  $SgId = aws ec2 describe-security-groups --region $Region --group-names $SgName --query "SecurityGroups[0].GroupId" --output text
}
foreach ($Port in @(22, 80, 443, 8000)) {
  aws ec2 authorize-security-group-ingress --region $Region --group-id $SgId --protocol tcp --port $Port --cidr 0.0.0.0/0 2>$null | Out-Null
}

Write-Host "[2/4] Creating SSH key pair ($KeyName.pem)..."
if (-not (Test-Path "$KeyName.pem")) {
  aws ec2 create-key-pair --region $Region --key-name $KeyName --query "KeyMaterial" --output text | Out-File -Encoding ascii "$KeyName.pem"
}

Write-Host "[3/4] Finding latest Ubuntu 24.04 AMI..."
$AmiId = aws ec2 describe-images --region $Region --owners 099720109477 `
  --filters "Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" `
  --query "sort_by(Images, &CreationDate)[-1].ImageId" --output text

Write-Host "[4/4] Launching EC2 instance ($InstanceType)..."
$InstanceId = aws ec2 run-instances --region $Region --image-id $AmiId --count 1 --instance-type $InstanceType `
  --key-name $KeyName --security-group-ids $SgId `
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=garuda-v7-prod}]" `
  --query "Instances[0].InstanceId" --output text

aws ec2 wait instance-running --region $Region --instance-ids $InstanceId
$PublicIp = aws ec2 describe-instances --region $Region --instance-ids $InstanceId `
  --query "Reservations[0].Instances[0].PublicIpAddress" --output text

Write-Host "EC2 Live at: http://${PublicIp}:8000"
