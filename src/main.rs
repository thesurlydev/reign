extern crate clap;
extern crate core;

use std::thread::sleep;
use std::time::Duration;

use aws_config::meta::region::RegionProviderChain;
use aws_config::RetryConfig;
use aws_sdk_ec2::Client;
use aws_sdk_ec2::Error;
use aws_sdk_ec2::model::{Filter, IamInstanceProfileSpecification, Instance,
                         InstanceNetworkInterfaceSpecification, InstanceType, Reservation,
                         ResourceType, Tag, TagSpecification};
use aws_sdk_ec2::output::DescribeInstancesOutput;
use clap::{AppSettings, Parser};
use serde_derive::{Deserialize, Serialize};

#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(version, setting = AppSettings::ArgRequiredElseHelp)]
struct Config {
    /// Name to tag instance with
    #[clap(short, long)]
    name: String,
    /// File containing arguments
    #[clap(short, long)]
    file: Option<String>,
    /// Instance type of the VM
    #[clap(short, long)]
    instance_type: String,
    /// Linux distribution
    #[clap(short, long)]
    distro: String,
    /// AMI to use for the VM
    #[clap(short, long)]
    ami: String,
    /// SSH user
    #[clap(short, long)]
    user: Option<String>,
    /// ID of the subnet to run the VM on
    #[clap(short, long)]
    subnet: String,
    /// Security group IDs
    #[clap(short, long)]
    groups: Vec<String>,
    /// Name of the IAM instance profile
    #[clap(short, long)]
    role: String,
    /// AWS profile
    #[clap(short, long)]
    profile: Option<String>,
}
/*
impl Default for Config {
    fn default() -> Self {
        Config {
            name: String::new(),
            instance_type: String::new(),
            distro: String::new(),
            ami: String::new(),
            ssh_user: String::new(),
            subnet: String::new(),
            security_group: String::new(),
            iam_role: String::from("digitalsanctum-role"),
            aws_account_id: String::new(),
            aws_profile: String::new(),
        }
    }
}*/


#[tokio::main]
async fn main() -> Result<(), Error> {
    let config: Config = Config::parse();
    println!("{:?}", config);

    let region_provider = RegionProviderChain::default_provider().or_else("us-west-2");
    let retry_config: RetryConfig = RetryConfig::default().with_max_attempts(5);
    let shared_config = aws_config::from_env().region(region_provider).retry_config(retry_config).load().await;
    let client = Client::new(&shared_config);

    let instance_id = ec2_run_instance(&client).await?;
    sleep(Duration::from_secs(2));
    let instance = ec2_wait_for_state(&client, instance_id, "running").await?;

    println!("{:?}", instance);

    // get public DNS
    /*if let Some(instance) = instance {
        let mut public_dns = String::default();
        for interface in instance.network_interfaces().unwrap_or_default() {
            if let Some(pub_dns) = interface.association().unwrap().public_dns_name() {
                public_dns = pub_dns.to_string();
            }
        }
        println!("Public DNS: {public_dns}");
    }*/

    Ok(())
}

async fn ec2_run_instance(client: &Client) -> Result<String, Error> {
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

    let run_instances_out = client
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
        panic!("InstanceId was not returned");
    };

    println!("InstanceId: {id}");

    Ok(id.to_string())
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