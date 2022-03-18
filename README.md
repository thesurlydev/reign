# reign

Quickly spin up compute.

## Terminate all instances

Useful when debugging.

```shell
aws ec2 describe-instances | gron | grep -iE 'instanceid' | cut -d'"' -f2 | xargs aws ec2 terminate-instances --instance-ids
```

## Road map

* 