# reign

Quickly spin up compute.


## Create a VM

Given a configuration like the following:
```json
{
  "name": "reign-test",
  "count": 1,
  "instance_type": "t3.nano",
  "ami": "ami-036d46416a34a611c",
  "user": "ubuntu",
  "subnet": "subnet-89ef61d3",
  "group": "sg-37d22f44",
  "iam_role": "digitalsanctum-role",
  "region": "us-west-2",
  "key": "beefcake",
  "profile": "default"
}
```




## Terminate all instances

Useful when debugging.

```shell
aws ec2 describe-instances | gron | grep -iE 'instanceid' | cut -d'"' -f2 | xargs aws ec2 terminate-instances --instance-ids
```

## Road map

* 