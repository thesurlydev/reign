extern crate base64;
extern crate clap;
extern crate core;
extern crate port_scanner;

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

use aws_config::meta::region::RegionProviderChain;
use aws_config::RetryConfig;
use aws_sdk_ec2::model::{
    IamInstanceProfileSpecification, Instance, InstanceNetworkInterfaceSpecification, InstanceType,
    Reservation, ResourceType, Tag, TagSpecification, InstanceStateName,
};
use aws_sdk_ec2::output::DescribeInstancesOutput;
use aws_sdk_ec2::Region;
use base64::encode;
use clap::{App, Arg, ArgMatches};
use port_scanner::scan_port_addr;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
struct CreateVmConfig {
    /// Name to tag instance with
    name: String,
    /// Instance type of the VM
    instance_type: String,
    /// Amazon Machine Image
    ami: String,
    /// SSH user
    user: String,
    /// ID of the subnet to run the VM on
    subnet: String,
    /// Security group ID
    group: String,
    /// Name of the IAM role
    iam_role: String,
    /// Name of the AWS region
    region: String,
    /// Key name
    key: String,
    /// Number of instances to run
    count: i32,
    /// AWS profile
    profile: String,
}

impl CreateVmConfig {
    fn new() -> CreateVmConfig {
        return CreateVmConfig {
            name: "".to_string(),
            instance_type: "".to_string(),
            ami: "".to_string(),
            user: "".to_string(),
            subnet: "".to_string(),
            group: "".to_string(),
            iam_role: "".to_string(),
            region: "".to_string(),
            key: "".to_string(),
            count: 0,
            profile: "".to_string(),
        };
    }

    fn merge(&self, args: &ArgMatches) -> CreateVmConfig {
        let mut m = self.clone();
        if let Some(name) = args.value_of("name") {
            m.name = String::from(name);
        }
        if let Some(count) = args.value_of("count") {
            m.count = count.parse().unwrap()
        }
        if let Some(profile) = args.value_of("profile") {
            m.profile = String::from(profile)
        }
        // TODO add other overrides

        m
    }
}

#[derive(Deserialize, Debug, Clone)]
struct ListVmConfig {
    name: String,
    region: String,
    profile: String,
}

impl ListVmConfig {
    fn new(name: String, region: String, profile: String) -> ListVmConfig {
        return ListVmConfig {
            name,
            region,
            profile,
        };
    }

    fn merge(&self, args: &ArgMatches) -> ListVmConfig {
        let mut m = self.clone();
        if let Some(name) = args.value_of("name") {
            m.name = String::from(name);
        }
        if let Some(region) = args.value_of("region") {
            m.region = String::from(region)
        }
        if let Some(profile) = args.value_of("profile") {
            m.profile = String::from(profile)
        }
        m
    }
}

#[derive(Deserialize, Debug, Clone)]
struct DestroyVmConfig {
    /// Name to tag instance with
    name: String,
    /// Name of the AWS region
    region: String,
    /// AWS profile
    profile: String,
}

impl DestroyVmConfig {
    fn new(name: String, region: String, profile: String) -> DestroyVmConfig {
        return DestroyVmConfig {
            name,
            region,
            profile,
        };
    }

    fn merge(&self, args: &ArgMatches) -> DestroyVmConfig {
        let mut m = self.clone();
        if let Some(name) = args.value_of("name") {
            m.name = String::from(name);
        }
        if let Some(region) = args.value_of("region") {
            m.region = String::from(region)
        }
        if let Some(profile) = args.value_of("profile") {
            m.profile = String::from(profile)
        }
        m
    }
}

fn load_config_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<Option<CreateVmConfig>, Box<dyn Error>> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(None);
    }
    println!("Reading config from file: {}", p.display());
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let c = serde_json::from_reader(reader)?;
    Ok(c)
}

const REIGN_DEFAULT: &str = "reign.json";

#[tokio::main]
async fn main() -> Result<(), aws_sdk_ec2::Error> {
    let matches = App::new("reign")
        .about("Quickly spin up compute")
        .subcommand(
            App::new("create").subcommand(
                App::new("vm")
                    .arg(
                        Arg::new("name")
                            .short('n')
                            .long("name")
                            .help("Value given to the 'Name' tag")
                            .takes_value(true)
                            .value_name("NAME")
                            .env("REIGN_VM_NAME"),
                    )
                    .arg(
                        Arg::new("instance_type")
                            .short('t')
                            .long("instance_type")
                            .help("Instance type of the VM")
                            .takes_value(true)
                            .value_name("INSTANCE_TYPE")
                            .env("REIGN_VM_INSTANCE_TYPE"),
                    )
                    .arg(
                        Arg::new("ami")
                            .short('a')
                            .long("ami")
                            .help("Amazon Machine Image")
                            .takes_value(true)
                            .value_name("AMI")
                            .env("REIGN_VM_MACHINE_IMAGE"),
                    )
                    .arg(
                        Arg::new("user")
                            .short('u')
                            .long("user")
                            .help("SSH user")
                            .takes_value(true)
                            .value_name("SSH_USER")
                            .env("REIGN_VM_SSH_USER"),
                    )
                    .arg(
                        Arg::new("subnet")
                            .short('s')
                            .long("subnet")
                            .help("Subnet ID")
                            .takes_value(true)
                            .value_name("SUBNET_ID")
                            .env("REIGN_VM_SUBNET_ID"),
                    )
                    .arg(
                        Arg::new("group")
                            .long("security_group")
                            .help("Security group ID")
                            .takes_value(true)
                            .value_name("SECURITY_GROUP_ID")
                            .env("REIGN_VM_SECURITY_GROUP_ID"),
                    )
                    .arg(
                        Arg::new("iam-role")
                            .short('r')
                            .long("iam-role")
                            .help("IAM role name")
                            .takes_value(true)
                            .value_name("IAM_ROLE")
                            .env("REIGN_VM_IAM_ROLE"),
                    )
                    .arg(
                        Arg::new("region")
                            .long("region")
                            .help("Region to create the VM in")
                            .takes_value(true)
                            .value_name("REGION")
                            .env("REIGN_VM_REGION"),
                    )
                    .arg(
                        Arg::new("profile")
                            .short('p')
                            .long("profile")
                            .help("Profile to use")
                            .takes_value(true)
                            .value_name("PROFILE")
                            .env("REIGN_VM_PROFILE"),
                    )
                    .arg(
                        Arg::new("key-pair")
                            .short('k')
                            .long("key-pair")
                            .help("Key pair to associate with the VM")
                            .takes_value(true)
                            .value_name("KEY_PAIR")
                            .env("REIGN_VM_KEY_PAIR"),
                    )
                    .arg(
                        Arg::new("count")
                            .short('c')
                            .long("count")
                            .help("Number of VMs to create")
                            .takes_value(true)
                            .value_name("COUNT")
                            .env("REIGN_VM_COUNT"),
                    ),
            ),
        )
        .subcommand(
            App::new("destroy")
                .subcommand(
                    App::new("vm").arg(
                        Arg::new("name")
                            .short('n')
                            .long("name")
                            .help("Name of the vm to destroy")
                            .takes_value(true)
                            .value_name("NAME")
                            .env("REIGN_VM_NAME"),
                    ),
                )
                .arg(
                    Arg::new("region")
                        .long("region")
                        .help("Region the VM is in")
                        .takes_value(true)
                        .value_name("REGION")
                        .env("REIGN_VM_REGION"),
                )
                .arg(
                    Arg::new("profile")
                        .short('p')
                        .long("profile")
                        .help("Profile to use")
                        .takes_value(true)
                        .value_name("PROFILE")
                        .env("REIGN_VM_PROFILE"),
                ),
        )
        .subcommand(
            App::new("list")
                .arg(
                    Arg::new("name")
                        .short('n')
                        .long("name")
                        .help("Name of the vm")
                        .takes_value(true)
                        .value_name("NAME")
                        .env("REIGN_VM_NAME"),
                )
                .arg(
                    Arg::new("region")
                        .long("region")
                        .help("Region the VM is in")
                        .takes_value(true)
                        .value_name("REGION")
                        .env("REIGN_VM_REGION"),
                )
                .arg(
                    Arg::new("profile")
                        .short('p')
                        .long("profile")
                        .help("Profile to use")
                        .takes_value(true)
                        .value_name("PROFILE")
                        .env("REIGN_VM_PROFILE"),
                ),
        )
        .get_matches();

    if let Some(cmd) = matches.subcommand_matches("create") {
        if let Some(compute) = cmd.subcommand_matches("vm") {
            println!("create vm!");

            // load default config
            let p = Path::new(REIGN_DEFAULT);

            // merge with args
            let merged = match load_config_from_file(p) {
                Ok(dc) => match dc {
                    Some(c) => c.merge(compute),
                    None => CreateVmConfig::new().merge(compute),
                },
                Err(_) => CreateVmConfig::new().merge(compute),
            };
            // println!("merged: {:?}", merged);

            // create client
            let conf_region: Region = Region::new(merged.to_owned().region);
            let region_provider = RegionProviderChain::default_provider().or_else(conf_region);
            let retry_config: RetryConfig = RetryConfig::default().with_max_attempts(5);
            let shared_config = aws_config::from_env()
                .region(region_provider)
                .retry_config(retry_config)
                .load()
                .await;
            let client = aws_sdk_ec2::Client::new(&shared_config);

            // create vm(s)
            create_vm(&client, &merged).await?;
        }
    } else if let Some(_cmd) = matches.subcommand_matches("list") {
        // load default config
        let p = Path::new(REIGN_DEFAULT);

        // merge with args
        let merged = match load_config_from_file(p) {
            Ok(dc) => match dc {
                Some(c) => c,
                None => CreateVmConfig::new(),
            },
            Err(_) => CreateVmConfig::new(),
        };
        // println!("merged: {:?}", merged);

        // create listconfig from createconfig
        let list_config = ListVmConfig::new(merged.name, merged.region, merged.profile);

        // create client
        let conf_region: Region = Region::new(list_config.to_owned().region);
        let region_provider = RegionProviderChain::default_provider().or_else(conf_region);
        let retry_config: RetryConfig = RetryConfig::default().with_max_attempts(5);
        let shared_config = aws_config::from_env()
            .region(region_provider)
            .retry_config(retry_config)
            .load()
            .await;
        let client = aws_sdk_ec2::Client::new(&shared_config);

        list_vms(&client, &list_config).await?;
    } else if let Some(cmd) = matches.subcommand_matches("destroy") {
        if let Some(compute) = cmd.subcommand_matches("vm") {
            // load default config
            let p = Path::new(REIGN_DEFAULT);

            // merge with args
            let merged = match load_config_from_file(p) {
                Ok(dc) => match dc {
                    Some(c) => c.merge(compute),
                    None => CreateVmConfig::new().merge(compute),
                },
                Err(_) => CreateVmConfig::new().merge(compute),
            };
            // println!("merged: {:?}", merged);

            // create destroyconfig from createconfig
            let destroy_config = DestroyVmConfig::new(merged.name, merged.region, merged.profile);

            // create client
            let conf_region: Region = Region::new(destroy_config.to_owned().region);
            let region_provider = RegionProviderChain::default_provider().or_else(conf_region);
            let retry_config: RetryConfig = RetryConfig::default().with_max_attempts(5);
            let shared_config = aws_config::from_env()
                .region(region_provider)
                .retry_config(retry_config)
                .load()
                .await;
            let client = aws_sdk_ec2::Client::new(&shared_config);

            destroy_vm(&client, &destroy_config).await?;
        }
    }

    Ok(())
}

async fn list_vms(
    client: &aws_sdk_ec2::Client,
    _config: &ListVmConfig,
) -> Result<(), aws_sdk_ec2::Error> {
    let resp = client.describe_instances().send().await?;

    for reservation in resp.reservations().unwrap_or_default() {
        for instance in reservation.instances().unwrap_or_default() {
            println!("");
            let name_tag = instance
                .tags()
                .unwrap_or_default()
                .iter()
                .find(|t| t.key().unwrap_or_default() == "Name");
            println!("       Name: {}", name_tag.unwrap().value().unwrap());
            println!("Instance ID: {}", instance.instance_id().unwrap());
            println!(
                "      State: {:?}",
                instance.state().unwrap().name().unwrap()
            );
            println!("--------------------");
        }
    }

    Ok(())
}

async fn destroy_vm(
    client: &aws_sdk_ec2::Client,
    config: &DestroyVmConfig,
) -> Result<(), aws_sdk_ec2::Error> {
    let resp = client.describe_instances().send().await?;

    for reservation in resp.reservations().unwrap_or_default() {
        for instance in reservation.instances().unwrap_or_default() {
            let name_tag = instance
                .tags()
                .unwrap_or_default()
                .iter()
                .find(|t| t.key().unwrap_or_default() == "Name").unwrap().value().unwrap();
            let state = instance.state().unwrap().name().unwrap().as_str();                            

            if name_tag == config.name && InstanceStateName::Running.as_str() == state {
                let instance_id = instance.instance_id().unwrap().to_string();
                println!("Terminating instance: {}", instance_id);
                let instance_ids = Some(vec![instance_id]);
                client
                    .terminate_instances()
                    .set_instance_ids(instance_ids)
                    .send()
                    .await?;
            }
        }
    }

    Ok(())
}

async fn create_vm(
    client: &aws_sdk_ec2::Client,
    config: &CreateVmConfig,
) -> Result<(), aws_sdk_ec2::Error> {
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
    println!(
        "Connection string: ssh -i ~/.ssh/{}.pem {}@{public_dns}",
        config.key, config.user
    );
    println!();

    Ok(())
}

fn user_data() -> String {
    return encode(
        r#"#!/bin/bash

set -e

sudo apt update -y
echo "test" > ~/complete.txt
"#,
    );
}

async fn ec2_run_instance(
    client: &aws_sdk_ec2::Client,
    config: &CreateVmConfig,
) -> Result<String, aws_sdk_ec2::Error> {
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

async fn ec2_wait_for_state(
    client: &aws_sdk_ec2::Client,
    id: String,
    state: &str,
) -> Result<Instance, aws_sdk_ec2::Error> {
    let mut instance: Instance = Instance::builder().build();

    loop {
        let instance_ids = vec![id.to_owned()];
        let status_filter = aws_sdk_ec2::model::Filter::builder()
            .name("instance-state-name")
            .values(state)
            .build();
        let filters = vec![status_filter];
        let describe_instances_output: DescribeInstancesOutput = client
            .describe_instances()
            .set_instance_ids(Some(instance_ids))
            .set_filters(Some(filters))
            .send()
            .await?;

        let reservations: Vec<Reservation> =
            describe_instances_output.reservations.unwrap_or_default();
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
