extern crate core;

use std::thread::sleep;
use std::time::Duration;

use aws_sdk_ec2::model::{
    IamInstanceProfileSpecification, InstanceNetworkInterfaceSpecification, InstanceStateName,
    InstanceType, ResourceType, Tag, TagSpecification,
};
use aws_sdk_ec2::output::DescribeInstancesOutput;
use aws_sdk_ec2::Client;
use aws_sdk_ec2::Error;
/*
struct Config {
    name: String,
    instance_type: String,
    distro: String,
    ami: String,
    ssh_user: String,
    subnets: Vec<String>,
    security_group: String,
    iam_role: String,
    aws_account_id: String,
    aws_profile: String,
}*/

#[tokio::main]
async fn main() -> Result<(), Error> {
    let shared_config = aws_config::load_from_env().await;
    let ec2 = Client::new(&shared_config);

    // let regions = ec2.describe_regions().send().await?;
    // println!("{:#?}", regions);

    let network_spec = InstanceNetworkInterfaceSpecification::builder()
        .associate_public_ip_address(true)
        .device_index(0)
        .subnet_id("subnet-89ef61d3")
        .groups("sg-37d22f44")
        .build();

    let tag_spec = TagSpecification::builder()
        .resource_type(ResourceType::Instance)
        .tags(Tag::builder().key("Name").value("rust-test").build())
        .build();

    let iam_spec = IamInstanceProfileSpecification::builder()
        .name("digitalsanctum-role")
        .build();

    let run_instances_out = ec2
        .run_instances()
        .image_id("ami-036d46416a34a611c")
        .max_count(1)
        .min_count(1)
        .instance_type(InstanceType::T3Nano)
        .key_name("beefcake")
        .network_interfaces(network_spec)
        .iam_instance_profile(iam_spec)
        .tag_specifications(tag_spec)
        .send()
        .await?;

    let mut instance_id: Option<&str> = None;
    if let Some(instances) = &run_instances_out.instances {
        if let Some(instance) = instances.first() {
            if let Some(id) = &instance.instance_id {
                instance_id = Some(id);
            }
        }
    }

    let id: &str = if instance_id.is_some() {
        instance_id.unwrap()
    } else {
        panic!("instance_id was not returned");
    };

    println!("instanceId: {}", id);

    // TODO race condition here
    sleep(Duration::from_secs(1));
    loop {

        let resp: DescribeInstancesOutput =
            ec2.describe_instances().instance_ids(id).send().await?;

        let mut actual_state_name = &InstanceStateName::Unknown(String::from(""));

        for reservation in resp.reservations().unwrap_or_default() {
            for instance in reservation.instances().unwrap_or_default() {
                if let Some(instance_state_name) = instance.state().unwrap().name() {
                    actual_state_name = instance_state_name;
                }
            }
        }

        if let InstanceStateName::Running = actual_state_name {
            println!("instance is running");
            break;
        } else {
            sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}
