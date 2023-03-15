// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use std::sync::Arc;
use std::{
    collections::BTreeSet,
    fmt::{Debug, Display, Formatter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use crate::config::{Config, PersistedConfig, SuiClientConfig, SuiEnv};
use anyhow::{anyhow, ensure};
use bip32::DerivationPath;
use clap::*;
use colored::Colorize;
use fastcrypto::{
    encoding::{Base64, Encoding},
    traits::ToFromBytes,
};
use move_core_types::language_storage::TypeTag;
use move_package::BuildConfig as MoveBuildConfig;
use prettytable::Table;
use prettytable::{row, table};
use serde::Serialize;
use serde_json::{json, Value};
use sui_framework::build_move_package;
use sui_keys::keypair_file::read_keypair_from_file;
use sui_move::build::resolve_lock_file_path;
use sui_source_validation::{BytecodeSourceVerifier, SourceMode};
use sui_types::SUI_FRAMEWORK_OBJECT_ID;
use sui_types::digests::TransactionDigest;
use sui_types::error::SuiError;

use shared_crypto::intent::Intent;
use sui_framework_build::compiled_package::{
    build_from_resolution_graph, check_invalid_dependencies, check_unpublished_dependencies,
    gather_dependencies, BuildConfig,
};
use sui_json::SuiJsonValue;
use sui_json_rpc_types::{
    DynamicFieldPage, SuiObjectData, SuiObjectInfo, SuiObjectResponse, SuiRawData,
    SuiTransactionEffectsAPI, SuiTransactionResponse, SuiTransactionResponseOptions,
};
use sui_json_rpc_types::{SuiExecutionStatus, SuiObjectDataOptions};
use sui_keys::keystore::AccountKeystore;
use sui_sdk::SuiClient;
use sui_types::crypto::SignatureScheme;
use sui_types::dynamic_field::DynamicFieldType;
use sui_types::messages::CallArg;
use sui_types::signature::GenericSignature;
use sui_types::{
    base_types::{ObjectID, ObjectRef, SuiAddress},
    gas_coin::GasCoin,
    messages::{Transaction, VerifiedTransaction},
    object::Owner,
    parse_sui_type_tag, SUI_FRAMEWORK_ADDRESS,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

pub const EXAMPLE_NFT_NAME: &str = "Example NFT";
pub const EXAMPLE_NFT_DESCRIPTION: &str = "An NFT created by the Sui Command Line Tool";
pub const EXAMPLE_NFT_URL: &str =
    "ipfs://bafkreibngqhl3gaa7daob4i2vccziay2jjlp435cf66vhono7nrvww53ty";

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
pub enum SuiValidatorCommand {
    #[clap(name = "join-committee")]
    JoinCommittee {},

    /// Obtain all objects owned by the address
    #[clap(name = "leave-committee")]
    LeaveCommittee {},

    /// Obtain all gas objects owned by the address.
    #[clap(name = "update-next-epoch-protocol-pub-key")]
    UpdateNextEpochProtocolPubKey {
        #[clap(name = "keypair-path")]
        file: PathBuf,
    },

}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SuiValidatorCommandResponse {
    JoinCommittee(TransactionDigest),
    LeaveCommittee(TransactionDigest),
    UpdateNextEpochProtocolPubKey(TransactionDigest),
}


impl SuiValidatorCommand {
    pub async fn execute(
        self,
        context: &mut WalletContext,
    ) -> Result<SuiValidatorCommandResponse, anyhow::Error> {
        let ret = Ok(match self {
            SuiValidatorCommand::UpdateNextEpochProtocolPubKey {
                file,
            } => {
                let res = read_keypair_from_file(&file)?;

                let response = call_move(
                    SUI_FRAMEWORK_OBJECT_ID,
                    "sui_system",
                    "update_validator_next_epoch_protocol_pubkey",
                    vec![],
                    gas,
                    gas_budget.unwrap_or(100_000),
                    args,
                    context,
                )
                .await?;

                let data = bcs::from_bytes(
                    &Base64::try_from(tx_bytes)
                        .map_err(|e| anyhow!(e))?
                        .to_vec()
                        .map_err(|e| anyhow!(e))?,
                )?;

                let mut sigs = Vec::new();
                for sig in signatures {
                    sigs.push(
                        GenericSignature::from_bytes(
                            &Base64::try_from(sig)
                                .map_err(|e| anyhow!(e))?
                                .to_vec()
                                .map_err(|e| anyhow!(e))?,
                        )
                        .map_err(|e| anyhow!(e))?,
                    );
                }
                let verified =
                    Transaction::from_generic_sig_data(data, Intent::default(), sigs).verify()?;

                let response = context.execute_transaction(verified).await?;
                SuiClientCommandResult::ExecuteSignedTx(response)
            }
            SuiClientCommands::NewEnv { alias, rpc, ws } => {
                if context.config.envs.iter().any(|env| env.alias == alias) {
                    return Err(anyhow!(
                        "Environment config with name [{alias}] already exists."
                    ));
                }
                let env = SuiEnv { alias, rpc, ws };

                // Check urls are valid and server is reachable
                env.create_rpc_client(None).await?;
                context.config.envs.push(env.clone());
                context.config.save()?;
                SuiClientCommandResult::NewEnv(env)
            }
            SuiClientCommands::ActiveEnv => {
                SuiClientCommandResult::ActiveEnv(context.config.active_env.clone())
            }
            SuiClientCommands::Envs => SuiClientCommandResult::Envs(
                context.config.envs.clone(),
                context.config.active_env.clone(),
            ),
            SuiClientCommands::VerifySource {
                package_path,
                build_config,
                verify_deps,
                skip_source,
                address_override,
            } => {
                if skip_source && !verify_deps {
                    return Err(anyhow!(
                        "Source skipped and not verifying deps: Nothing to verify."
                    ));
                }

                let build_config =
                    resolve_lock_file_path(build_config, Some(package_path.clone()))?;

                let compiled_package = build_move_package(
                    &package_path,
                    BuildConfig {
                        config: build_config,
                        run_bytecode_verifier: true,
                        print_diags_to_stderr: true,
                    },
                )?;

                let client = context.get_client().await?;

                BytecodeSourceVerifier::new(client.read_api(), false)
                    .verify_package(
                        &compiled_package.package,
                        verify_deps,
                        match (skip_source, address_override) {
                            (true, _) => SourceMode::Skip,
                            (false, None) => SourceMode::Verify,
                            (false, Some(addr)) => SourceMode::VerifyAt(addr.into()),
                        },
                    )
                    .await?;

                SuiClientCommandResult::VerifySource
            }
        });
        ret
    }

    pub fn switch_env(config: &mut SuiClientConfig, env: &str) -> Result<(), anyhow::Error> {
        let env = Some(env.into());
        ensure!(config.get_env(&env).is_some(), "Environment config not found for [{env:?}], add new environment config using the `sui client new-env` command.");
        config.active_env = env;
        Ok(())
    }
}

pub struct WalletContext {
    pub config: PersistedConfig<SuiClientConfig>,
    request_timeout: Option<std::time::Duration>,
    client: Arc<RwLock<Option<SuiClient>>>,
}

impl WalletContext {
    pub async fn new(
        config_path: &Path,
        request_timeout: Option<std::time::Duration>,
    ) -> Result<Self, anyhow::Error> {
        let config: SuiClientConfig = PersistedConfig::read(config_path).map_err(|err| {
            err.context(format!(
                "Cannot open wallet config file at {:?}",
                config_path
            ))
        })?;

        let config = config.persisted(config_path);
        let context = Self {
            config,
            request_timeout,
            client: Default::default(),
        };
        Ok(context)
    }

    pub async fn get_client(&self) -> Result<SuiClient, anyhow::Error> {
        let read = self.client.read().await;

        Ok(if let Some(client) = read.as_ref() {
            client.clone()
        } else {
            drop(read);
            let client = self
                .config
                .get_active_env()?
                .create_rpc_client(self.request_timeout)
                .await?;

            if let Err(e) = client.check_api_version() {
                warn!("{e}");
                println!("{}", format!("[warn] {e}").yellow().bold());
            }
            self.client.write().await.insert(client).clone()
        })
    }

    pub fn active_address(&mut self) -> Result<SuiAddress, anyhow::Error> {
        if self.config.keystore.addresses().is_empty() {
            return Err(anyhow!(
                "No managed addresses. Create new address with `new-address` command."
            ));
        }

        // Ok to unwrap because we checked that config addresses not empty
        // Set it if not exists
        self.config.active_address = Some(
            self.config
                .active_address
                .unwrap_or(*self.config.keystore.addresses().get(0).unwrap()),
        );

        Ok(self.config.active_address.unwrap())
    }

    /// Get the latest object reference given a object id
    pub async fn get_object_ref(&self, object_id: ObjectID) -> Result<ObjectRef, anyhow::Error> {
        let client = self.get_client().await?;
        Ok(client
            .read_api()
            .get_object_with_options(object_id, SuiObjectDataOptions::new())
            .await?
            .into_object()?
            .object_ref())
    }

    /// Get all the gas objects (and conveniently, gas amounts) for the address
    pub async fn gas_objects(
        &self,
        address: SuiAddress,
    ) -> Result<Vec<(u64, SuiObjectData, SuiObjectInfo)>, anyhow::Error> {
        let client = self.get_client().await?;
        let object_refs = client
            .read_api()
            .get_objects_owned_by_address(address)
            .await?;
        let o_ref_clone = object_refs.clone();
        // TODO: We should ideally fetch the objects from local cache
        let mut values_objects = Vec::new();
        let oref_ids: Vec<ObjectID> = object_refs.into_iter().map(|oref| oref.object_id).collect();

        let responses = client
            .read_api()
            .multi_get_object_with_options(oref_ids, SuiObjectDataOptions::full_content())
            .await?;

        let pairs: Vec<_> = responses.iter().zip(o_ref_clone.into_iter()).collect();

        for (response, oref) in pairs {
            match response {
                SuiObjectResponse::Exists(o) => {
                    if matches!( &o.type_, Some(type_)  if type_.is_gas_coin()) {
                        // Okay to unwrap() since we already checked type
                        let gas_coin = GasCoin::try_from(o)?;
                        values_objects.push((gas_coin.value(), o.clone(), oref));
                    }
                }
                _ => continue,
            }
        }

        Ok(values_objects)
    }

    pub async fn get_object_owner(&self, id: &ObjectID) -> Result<SuiAddress, anyhow::Error> {
        let client = self.get_client().await?;
        let object = client
            .read_api()
            .get_object_with_options(*id, SuiObjectDataOptions::new().with_owner())
            .await?
            .into_object()?;
        Ok(object
            .owner
            .ok_or_else(|| anyhow!("Owner field is None"))?
            .get_owner_address()?)
    }

    pub async fn try_get_object_owner(
        &self,
        id: &Option<ObjectID>,
    ) -> Result<Option<SuiAddress>, anyhow::Error> {
        if let Some(id) = id {
            Ok(Some(self.get_object_owner(id).await?))
        } else {
            Ok(None)
        }
    }

    /// Find a gas object which fits the budget
    pub async fn gas_for_owner_budget(
        &self,
        address: SuiAddress,
        budget: u64,
        forbidden_gas_objects: BTreeSet<ObjectID>,
    ) -> Result<(u64, SuiObjectData), anyhow::Error> {
        for o in self.gas_objects(address).await.unwrap() {
            if o.0 >= budget && !forbidden_gas_objects.contains(&o.1.object_id) {
                return Ok((o.0, o.1));
            }
        }
        Err(anyhow!(
            "No non-argument gas objects found with value >= budget {budget}"
        ))
    }

    pub async fn execute_transaction(
        &self,
        tx: VerifiedTransaction,
    ) -> anyhow::Result<SuiTransactionResponse> {
        let client = self.get_client().await?;
        Ok(client
            .quorum_driver()
            .execute_transaction(
                tx,
                SuiTransactionResponseOptions::new()
                    .with_effects()
                    .with_events()
                    .with_input(),
                Some(sui_types::messages::ExecuteTransactionRequestType::WaitForLocalExecution),
            )
            .await?)
    }
}

impl Display for SuiClientCommandResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        match self {
            SuiClientCommandResult::Publish(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::Object(object_read) => {
                let object = unwrap_err_to_string(|| Ok(object_read.object()?));
                writeln!(writer, "{}", object)?;
            }
            SuiClientCommandResult::RawObject(raw_object_read) => {
                let raw_object = match raw_object_read.object() {
                    Ok(v) => match &v.bcs {
                        Some(SuiRawData::MoveObject(o)) => {
                            format!("{:?}\nNumber of bytes: {}", o.bcs_bytes, o.bcs_bytes.len())
                        }
                        Some(SuiRawData::Package(p)) => {
                            let mut temp = String::new();
                            let mut bcs_bytes = 0usize;
                            for m in &p.module_map {
                                temp.push_str(&format!("{:?}\n", m));
                                bcs_bytes += m.1.len()
                            }
                            format!("{}Number of bytes: {}", temp, bcs_bytes)
                        }
                        None => "Bcs field is None".to_string().red().to_string(),
                    },
                    Err(err) => format!("{err}").red().to_string(),
                };
                writeln!(writer, "{}", raw_object)?;
            }
            SuiClientCommandResult::Call(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::Transfer(time_elapsed, response) => {
                writeln!(writer, "Transfer confirmed after {} us", time_elapsed)?;
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::TransferSui(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::Pay(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::PaySui(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::PayAllSui(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::Addresses(addresses, active_address) => {
                writeln!(writer, "Showing {} results.", addresses.len())?;
                for address in addresses {
                    if *active_address == Some(*address) {
                        writeln!(writer, "{} <=", address)?;
                    } else {
                        writeln!(writer, "{}", address)?;
                    }
                }
            }
            SuiClientCommandResult::Objects(object_refs) => {
                writeln!(
                    writer,
                    " {0: ^42} | {1: ^10} | {2: ^44} | {3: ^15} | {4: ^40}",
                    "Object ID", "Version", "Digest", "Owner Type", "Object Type"
                )?;
                writeln!(writer, "{}", ["-"; 165].join(""))?;
                for oref in object_refs {
                    let owner_type = match oref.owner {
                        Owner::AddressOwner(_) => "AddressOwner",
                        Owner::ObjectOwner(_) => "object_owner",
                        Owner::Shared { .. } => "Shared",
                        Owner::Immutable => "Immutable",
                    };
                    writeln!(
                        writer,
                        " {0: ^42} | {1: ^10} | {2: ^44} | {3: ^15} | {4: ^40}",
                        oref.object_id,
                        oref.version.value(),
                        Base64::encode(oref.digest),
                        owner_type,
                        oref.type_
                    )?
                }
                writeln!(writer, "Showing {} results.", object_refs.len())?;
            }
            SuiClientCommandResult::DynamicFieldQuery(df_refs) => {
                let mut table: Table = table!([
                    "Name",
                    "Type",
                    "Object Type",
                    "Object Id",
                    "Version",
                    "Digest"
                ]);
                for df_ref in df_refs.data.iter() {
                    let df_type = match df_ref.type_ {
                        DynamicFieldType::DynamicField => "DynamicField",
                        DynamicFieldType::DynamicObject => "DynamicObject",
                    };
                    table.add_row(row![
                        df_ref.name,
                        df_type,
                        df_ref.object_type,
                        df_ref.object_id,
                        df_ref.version.value(),
                        Base64::encode(df_ref.digest)
                    ]);
                }
                write!(writer, "{table}")?;
                writeln!(writer, "Showing {} results.", df_refs.data.len())?;
                if let Some(cursor) = df_refs.next_cursor {
                    writeln!(writer, "Next cursor: {cursor}")?;
                }
            }
            SuiClientCommandResult::SyncClientState => {
                writeln!(writer, "Client state sync complete.")?;
            }
            // Do not use writer for new address output, which may get sent to logs.
            #[allow(clippy::print_in_format_impl)]
            SuiClientCommandResult::NewAddress((address, recovery_phrase, scheme)) => {
                println!(
                    "Created new keypair for address with scheme {:?}: [{address}]",
                    scheme
                );
                println!("Secret Recovery Phrase : [{recovery_phrase}]");
            }
            SuiClientCommandResult::Gas(gases) => {
                // TODO: generalize formatting of CLI
                writeln!(writer, " {0: ^42} | {1: ^11}", "Object ID", "Gas Value")?;
                writeln!(
                    writer,
                    "----------------------------------------------------------------------"
                )?;
                for gas in gases {
                    writeln!(writer, " {0: ^42} | {1: ^11}", gas.id(), gas.value())?;
                }
            }
            SuiClientCommandResult::SplitCoin(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::MergeCoin(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::Switch(response) => {
                write!(writer, "{}", response)?;
            }
            SuiClientCommandResult::ActiveAddress(response) => {
                match response {
                    Some(r) => write!(writer, "{}", r)?,
                    None => write!(writer, "None")?,
                };
            }
            SuiClientCommandResult::CreateExampleNFT(object_read) => {
                // TODO: display the content of the object
                let object = unwrap_err_to_string(|| Ok(object_read.object()?));
                writeln!(writer, "{}\n", "Successfully created an ExampleNFT:".bold())?;
                writeln!(writer, "{}", object)?;
            }
            SuiClientCommandResult::ExecuteSignedTx(response) => {
                write!(writer, "{}", write_transaction_response(response)?)?;
            }
            SuiClientCommandResult::SerializeTransferSui(data) => {
                writeln!(writer, "Raw tx_bytes to execute: {}", data)?;
            }
            SuiClientCommandResult::ActiveEnv(env) => {
                write!(writer, "{}", env.as_deref().unwrap_or("None"))?;
            }
            SuiClientCommandResult::NewEnv(env) => {
                writeln!(writer, "Added new Sui env [{}] to config.", env.alias)?;
            }
            SuiClientCommandResult::Envs(envs, active) => {
                for env in envs {
                    write!(writer, "{} => {}", env.alias, env.rpc)?;
                    if Some(env.alias.as_str()) == active.as_deref() {
                        write!(writer, " (active)")?;
                    }
                    writeln!(writer)?;
                }
            }
            SuiClientCommandResult::VerifySource => {
                writeln!(writer, "Source verification succeeded!")?;
            }
        }
        write!(f, "{}", writer.trim_end_matches('\n'))
    }
}

pub async fn call_move(
    package: ObjectID,
    module: &str,
    function: &str,
    type_args: Vec<TypeTag>,
    gas: Option<ObjectID>,
    gas_budget: u64,
    args: Vec<SuiJsonValue>,
    context: &mut WalletContext,
) -> Result<SuiTransactionResponse, anyhow::Error> {
    // Convert all numeric input to String, this will allow number input from the CLI without failing SuiJSON's checks.
    let args = args
        .into_iter()
        .map(|value| SuiJsonValue::new(convert_number_to_string(value.to_json_value())))
        .collect::<Result<_, _>>()?;

    let gas_owner = context.try_get_object_owner(&gas).await?;
    let sender = gas_owner.unwrap_or(context.active_address()?);

    let client = context.get_client().await?;
    let mut args = vec![
        CallArg::Object(ObjectArg::SharedObject {
            id: SUI_SYSTEM_STATE_OBJECT_ID,
            initial_shared_version: SUI_SYSTEM_STATE_OBJECT_SHARED_VERSION,
            mutable: true,
        }),
        CallArg::Pure(
            bcs::to_bytes(&new_protocol_key_pair_copy.public().as_bytes().to_vec()).unwrap(),
        ),
        CallArg::Pure(bcs::to_bytes(&pop.as_bytes().to_vec()).unwrap()),
    ];
    let data = client
        .transaction_builder()
        .move_call(
            sender,
            package,
            module,
            function,
            vec![],
            args,
            gas,
            gas_budget,
        )
        .await?;
    let signature = context
        .config
        .keystore
        .sign_secure(&sender, &data, Intent::default())?;
    let transaction = Transaction::from_data(data, Intent::default(), vec![signature]).verify()?;

    let response = context.execute_transaction(transaction).await?;
    let effects = response
        .effects
        .as_ref()
        .ok_or_else(|| anyhow!("Effects from SuiTransactionResult should not be empty"))?;
    if matches!(effects.status(), SuiExecutionStatus::Failure { .. }) {
        return Err(anyhow!("Error calling module: {:#?}", effects.status()));
    }
    Ok(response)
}

fn convert_number_to_string(value: Value) -> Value {
    match value {
        Value::Number(n) => Value::String(n.to_string()),
        Value::Array(a) => Value::Array(a.into_iter().map(convert_number_to_string).collect()),
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, v)| (k, convert_number_to_string(v)))
                .collect(),
        ),
        _ => value,
    }
}

fn unwrap_or<'a>(val: &'a Option<String>, default: &'a str) -> &'a str {
    match val {
        Some(v) => v,
        None => default,
    }
}

fn write_transaction_response(response: &SuiTransactionResponse) -> Result<String, fmt::Error> {
    let mut writer = String::new();
    writeln!(writer, "{}", "----- Transaction Data ----".bold())?;
    if let Some(t) = &response.transaction {
        write!(writer, "{}", t)?;
    }

    writeln!(writer, "{}", "----- Transaction Effects ----".bold())?;
    if let Some(e) = &response.effects {
        write!(writer, "{}", e)?;
    }
    Ok(writer)
}

impl Debug for SuiClientCommandResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = unwrap_err_to_string(|| match self {
            SuiClientCommandResult::Object(object_read) => {
                let object = object_read.object()?;
                Ok(serde_json::to_string_pretty(&object)?)
            }
            SuiClientCommandResult::RawObject(raw_object_read) => {
                let raw_object = raw_object_read.object()?;
                Ok(serde_json::to_string_pretty(&raw_object)?)
            }
            _ => Ok(serde_json::to_string_pretty(self)?),
        });
        write!(f, "{}", s)
    }
}

fn unwrap_err_to_string<T: Display, F: FnOnce() -> Result<T, anyhow::Error>>(func: F) -> String {
    match func() {
        Ok(s) => format!("{s}"),
        Err(err) => format!("{err}").red().to_string(),
    }
}

impl SuiClientCommandResult {
    pub fn print(&self, pretty: bool) {
        let line = if pretty {
            format!("{self}")
        } else {
            format!("{:?}", self)
        };
        // Log line by line
        for line in line.lines() {
            // Logs write to a file on the side.  Print to stdout and also log to file, for tests to pass.
            println!("{line}");
            info!("{line}")
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SuiClientCommandResult {
    Publish(SuiTransactionResponse),
    VerifySource,
    Object(SuiObjectResponse),
    RawObject(SuiObjectResponse),
    Call(SuiTransactionResponse),
    Transfer(
        // Skipping serialisation for elapsed time.
        #[serde(skip)] u128,
        SuiTransactionResponse,
    ),
    TransferSui(SuiTransactionResponse),
    Pay(SuiTransactionResponse),
    PaySui(SuiTransactionResponse),
    PayAllSui(SuiTransactionResponse),
    Addresses(Vec<SuiAddress>, Option<SuiAddress>),
    Objects(Vec<SuiObjectInfo>),
    DynamicFieldQuery(DynamicFieldPage),
    SyncClientState,
    NewAddress((SuiAddress, String, SignatureScheme)),
    Gas(Vec<GasCoin>),
    SplitCoin(SuiTransactionResponse),
    MergeCoin(SuiTransactionResponse),
    Switch(SwitchResponse),
    ActiveAddress(Option<SuiAddress>),
    ActiveEnv(Option<String>),
    Envs(Vec<SuiEnv>, Option<String>),
    CreateExampleNFT(SuiObjectResponse),
    SerializeTransferSui(String),
    ExecuteSignedTx(SuiTransactionResponse),
    NewEnv(SuiEnv),
}

#[derive(Serialize, Clone, Debug)]
pub struct SwitchResponse {
    /// Active address
    pub address: Option<SuiAddress>,
    pub env: Option<String>,
}

impl Display for SwitchResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut writer = String::new();
        if let Some(addr) = self.address {
            writeln!(writer, "Active address switched to {addr}")?;
        }
        if let Some(env) = &self.env {
            writeln!(writer, "Active environment switched to [{env}]")?;
        }
        write!(f, "{}", writer)
    }
}
