extern crate clap;
extern crate core;
extern crate port_scanner;
extern crate base64;

use base64::{encode};

use port_scanner::scan_port_addr;

use std::thread::sleep;
use std::time::Duration;

use aws_config::meta::region::RegionProviderChain;
use aws_config::RetryConfig;
use aws_sdk_ec2::{Client, Region};
use aws_sdk_ec2::Error;
use aws_sdk_ec2::model::{Filter, IamInstanceProfileSpecification, Instance, InstanceNetworkInterfaceSpecification, InstanceType, Reservation, ResourceType, Tag, TagSpecification};
use aws_sdk_ec2::output::DescribeInstancesOutput;
use clap::{AppSettings, Parser};

#[derive(Parser, Debug, PartialEq, Clone, Ord, PartialOrd, Eq)]
#[clap(version, setting = AppSettings::ArgRequiredElseHelp)]
struct Config {
    /// Name to tag instance with
    #[clap(short, long)]
    name: String,
    /// File containing arguments
    // #[clap(short, long)]
    // file: Option<String>,
    /// Instance type of the VM
    #[clap(short, long, default_value = "t3.nano")]
    instance_type: String,
    /// Amazon Machine Image
    #[clap(short, long, default_value = "ami-036d46416a34a611c")]
    ami: String,
    /// SSH user
    #[clap(short, long, default_value = "ubuntu")]
    user: String,
    /// ID of the subnet to run the VM on
    #[clap(short, long, default_value = "subnet-89ef61d3")]
    subnet: String,
    /// Security group ID
    #[clap(short, long, default_value = "sg-37d22f44")]
    group: String,
    /// Name of the IAM role
    #[clap(long, default_value = "digitalsanctum-role")]
    iam_role: String,
    /// Name of the AWS region
    #[clap(short, long, default_value = "us-west-2", env = "AWS_REGION")]
    region: String,
    /// AWS profile
    #[clap(short, long, env = "AWS_PROFILE")]
    profile: Option<String>,
    /// Key name
    #[clap(short, long, default_value = "beefcake")]
    key: String,
    /// Number of instances to run
    #[clap(short, long, default_value = "1")]
    count: i32,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config: Config = Config::parse();

    let conf_region: Region = Region::new(config.to_owned().region);

    let region_provider = RegionProviderChain::default_provider().or_else(conf_region);
    let retry_config: RetryConfig = RetryConfig::default().with_max_attempts(5);
    let shared_config = aws_config::from_env().region(region_provider).retry_config(retry_config).load().await;
    let client = Client::new(&shared_config);

    // run EC2 instance
    let instance_id = ec2_run_instance(&client, &config).await?;
    println!("InstanceId: {instance_id}");
    sleep(Duration::from_secs(2));

    // wait for running state
    let instance = ec2_wait_for_state(&client, instance_id, "running").await?;
    println!("Instance is running");

    // get public DNS
    let mut public_dns = String::default();
    for interface in instance.network_interfaces().unwrap_or_default() {
        if let Some(pub_dns) = interface.association().unwrap().public_dns_name() {
            public_dns = pub_dns.to_string();
        }
    }
    println!("Public DNS: {public_dns}");

    // wait for SSH port to become available
    let address = format!("{public_dns}:22");
    wait_for_open_port(&address).await;
    println!("SSH port is now available");
    println!();
    println!("Connection string: ssh -i ~/.ssh/{}.pem {}@{public_dns}", config.key, config.user);
    println!();

    Ok(())
}

fn user_data() -> String {
    return encode(r#"#!/bin/bash

set -e

echo "test" > /home/ubuntu/test.txt
"#);
}

async fn ec2_run_instance(client: &Client, config: &Config) -> Result<String, Error> {
    let network_spec = InstanceNetworkInterfaceSpecification::builder()
        .associate_public_ip_address(true)
        .device_index(0)
        .subnet_id(&config.subnet)
        .groups(&config.group)
        .build();

    let tag_spec = TagSpecification::builder()
        .resource_type(ResourceType::Instance)
        .tags(Tag::builder().key("Name").value(&config.name).build())
        .build();

    let iam_spec = IamInstanceProfileSpecification::builder()
        .name(&config.iam_role)
        .build();

    let instance_type = InstanceType::from(config.instance_type.as_str());

    let user_data = Some(user_data());

    let run_instances_out = client
        .run_instances()
        .set_user_data(user_data)
        .image_id(&config.ami)
        .max_count(config.count)
        .min_count(config.count)
        .instance_type(instance_type)
        .key_name(&config.key)
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
        panic!("InstanceId was not returned");
    };

    Ok(id.to_string())
}

async fn wait_for_open_port(address: &String) {
    loop {
        if scan_port_addr(address) {
            break;
        } else {
            sleep(Duration::from_millis(500))
        }
    }
}

async fn ec2_wait_for_state(client: &Client, id: String, state: &str) -> Result<Instance, Error> {
    let mut instance: Instance = Instance::builder().build();

    loop {
        let instance_ids = vec![id.to_owned()];
        let status_filter = Filter::builder().name("instance-state-name").values(state).build();
        let filters = vec![status_filter];
        let describe_instances_output: DescribeInstancesOutput = client.describe_instances()
            .set_instance_ids(Some(instance_ids))
            .set_filters(Some(filters))
            .send().await?;

        let reservations: Vec<Reservation> = describe_instances_output.reservations.unwrap_or_default();
        if reservations.len() == 1 {
            let reservation: Reservation = reservations.to_owned().pop().unwrap();
            let instances = reservation.instances.unwrap_or_default();
            instance = instances.first().unwrap().to_owned();
            break;
        } else {
            sleep(Duration::from_millis(200))
        }
    }
    Ok(instance)
}