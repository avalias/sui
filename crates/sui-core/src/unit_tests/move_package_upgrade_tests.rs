// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use move_core_types::ident_str;
use sui_framework_build::compiled_package::BuildConfig;
use sui_types::{
    base_types::{ObjectID, ObjectRef},
    crypto::{get_key_pair, AccountKeyPair},
    messages::{
        Argument, CommandArgumentError, ExecutionFailureStatus, ObjectArg, PackageUpgradeError,
        ProgrammableTransaction, TransactionEffects,
    },
    move_package::{UPGRADE_POLICY_COMPATIBLE, UPGRADE_POLICY_DEP_ONLY},
    object::Object,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
};

use std::path::PathBuf;

use crate::authority::{
    authority_tests::{execute_programmable_transaction, init_state},
    move_integration_tests::build_and_publish_test_package_with_upgrade_cap,
};

// TODO(tzakian): additional tests:
// * Complex upgrade (add struct, change private + friend function, add a module, and add a dep)
// * Invalid upgrade (change a public function, change a struct field)
// * Multiple upgrades
// * Invalid dependencies:
//   - Missing dependencies (this might be harder since we will need to mess with the hashing).
//   - Duplicate dependencies
// TODO(tzakian): Need to determine how best to enable package upgrades in the protocol config.

macro_rules! move_call {
    {$builder:expr, ($addr:expr)::$module_name:ident::$func:ident($($args:expr),* $(,)?)} => {
        $builder.programmable_move_call(
            $addr,
            ident_str!(stringify!($module_name)).to_owned(),
            ident_str!(stringify!($func)).to_owned(),
            vec![],
            vec![$($args),*],
        )
    }
}

pub fn build_upgrade_test_modules(test_dir: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    let build_config = BuildConfig::new_for_testing();
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.extend(["src", "unit_tests", "data", "move_upgrade", test_dir]);
    let package = sui_framework::build_move_package(&path, build_config).unwrap();
    (
        package.get_package_digest().to_vec(),
        package.get_package_bytes(true),
    )
}

pub async fn run_upgrade_test(
    base_package_name: &str,
    pt: impl FnOnce(ObjectRef, ObjectRef, ObjectRef) -> ProgrammableTransaction,
) -> TransactionEffects {
    let (sender, sender_key): (_, AccountKeyPair) = get_key_pair();
    let gas_object_id = ObjectID::random();
    let gas_object = Object::with_id_owner_gas_for_testing(gas_object_id, sender, 100000);
    let authority_state = init_state().await;
    authority_state.insert_genesis_object(gas_object).await;

    let (package, cap) = build_and_publish_test_package_with_upgrade_cap(
        &authority_state,
        &sender,
        &sender_key,
        &gas_object_id,
        base_package_name,
        true,
    )
    .await;

    let framework_object_ref = authority_state.get_framework_object_ref().await.unwrap();
    let txn = pt(package, cap, framework_object_ref);
    execute_programmable_transaction(&authority_state, &gas_object_id, &sender, &sender_key, txn)
        .await
        .unwrap()
}

#[tokio::test]
async fn test_upgrade_module_happy_path() {
    let TransactionEffects::V1(effects) =
        run_upgrade_test("move_upgrade/base", |package, cap, framework_object_ref| {
            let mut builder = ProgrammableTransactionBuilder::new();
            let current_package_id = package.0;
            let (digest, modules) = build_upgrade_test_modules("basic_compatibility_valid");

            // We take as input the upgrade cap
            builder.obj(ObjectArg::ImmOrOwnedObject(cap)).unwrap();

            // Create the upgrade ticket
            let upgrade_arg = builder.pure(UPGRADE_POLICY_COMPATIBLE).unwrap();
            let digest_arg = builder.pure(digest).unwrap();
            let upgrade_ticket = move_call! {
                builder,
                (framework_object_ref.0)::package::authorize_upgrade(Argument::Input(0), upgrade_arg, digest_arg)
            };
            let upgrade_receipt =
                builder.upgrade(current_package_id, upgrade_ticket, vec![], modules);
            move_call! {
                builder,
                (framework_object_ref.0)::package::commit_upgrade(Argument::Input(0), upgrade_receipt)
            };

            builder.finish()
        })
        .await;

    assert!(effects.status.is_ok());
}

#[tokio::test]
async fn test_upgrade_module_incorrect_digest() {
    let mut actual_digest = vec![];
    let TransactionEffects::V1(effects) =
        run_upgrade_test("move_upgrade/base", |package, cap, framework_object_ref| {
            let mut builder = ProgrammableTransactionBuilder::new();
            let current_package_id = package.0;
            let (digest, modules) = build_upgrade_test_modules("basic_compatibility_valid");
            let bad_digest: Vec<u8> = digest.iter().map(|_| 0).collect();
            actual_digest = digest;

            builder.obj(ObjectArg::ImmOrOwnedObject(cap)).unwrap();
            let upgrade_arg = builder.pure(UPGRADE_POLICY_COMPATIBLE).unwrap();
            let digest_arg = builder.pure(bad_digest).unwrap();
            let upgrade_ticket = move_call! {
                builder,
                (framework_object_ref.0)::package::authorize_upgrade(Argument::Input(0), upgrade_arg, digest_arg)
            };
            builder.upgrade(current_package_id, upgrade_ticket, vec![], modules);
            builder.finish()
        })
        .await;

    assert_eq!(
        effects.status.unwrap_err().0,
        ExecutionFailureStatus::PackageUpgradeError {
            upgrade_error: PackageUpgradeError::DigestDoesNotMatch {
                digest: actual_digest
            }
        }
    );
}

#[tokio::test]
async fn test_upgrade_module_dep_only_upgrade_policy() {
    let TransactionEffects::V1(effects) =
        run_upgrade_test("move_upgrade/base", |package, cap, framework_object_ref| {
            let mut builder = ProgrammableTransactionBuilder::new();
            let current_package_id = package.0;
            let (digest, modules) = build_upgrade_test_modules("basic_compatibility_valid");

            // We take as input the upgrade cap
            builder.obj(ObjectArg::ImmOrOwnedObject(cap)).unwrap();

            // Create the upgrade ticket
            let upgrade_arg = builder.pure(UPGRADE_POLICY_DEP_ONLY).unwrap();
            let digest_arg = builder.pure(digest).unwrap();
            move_call! {
                builder,
                (framework_object_ref.0)::package::only_dep_upgrades(Argument::Input(0))
            };
            let upgrade_ticket = move_call! {
                builder,
                (framework_object_ref.0)::package::authorize_upgrade(Argument::Input(0), upgrade_arg, digest_arg)
            };
            builder.upgrade(current_package_id, upgrade_ticket, vec![], modules);
            builder.finish()
        })
        .await;

    // An error currently because we only support compatible upgrades
    assert_eq!(
        effects.status.unwrap_err().0,
        ExecutionFailureStatus::FeatureNotYetSupported
    );
}

#[tokio::test]
async fn test_upgrade_module_not_a_ticket() {
    let TransactionEffects::V1(effects) = run_upgrade_test(
        "move_upgrade/base",
        |package, cap, _framework_object_ref| {
            let mut builder = ProgrammableTransactionBuilder::new();
            let current_package_id = package.0;
            let (_, modules) = build_upgrade_test_modules("basic_compatibility_valid");

            // We take as input the upgrade cap
            builder.obj(ObjectArg::ImmOrOwnedObject(cap)).unwrap();
            builder.upgrade(current_package_id, Argument::Input(0), vec![], modules);
            builder.finish()
        },
    )
    .await;

    // An error currently because we only support compatible upgrades
    assert_eq!(
        effects.status.unwrap_err().0,
        ExecutionFailureStatus::CommandArgumentError {
            arg_idx: 0,
            kind: CommandArgumentError::TypeMismatch
        }
    );
}

#[tokio::test]
async fn test_upgrade_ticket_doesnt_match() {
    let TransactionEffects::V1(effects) = run_upgrade_test(
        "move_upgrade/base",
        |_package, cap, framework_object_ref| {
            let mut builder = ProgrammableTransactionBuilder::new();
            let stdlib_pkg_id = ObjectID::from_hex_literal("0x1").unwrap();
            let (digest, modules) = build_upgrade_test_modules("basic_compatibility_valid");
            // We take as input the upgrade cap
            builder.obj(ObjectArg::ImmOrOwnedObject(cap)).unwrap();
            // Create the upgrade ticket
            let upgrade_arg = builder.pure(UPGRADE_POLICY_COMPATIBLE).unwrap();
            let digest_arg = builder.pure(digest).unwrap();
            let upgrade_ticket = move_call! {
                builder,
                (framework_object_ref.0)::package::authorize_upgrade(Argument::Input(0), upgrade_arg, digest_arg)
            };
            builder.upgrade(stdlib_pkg_id, upgrade_ticket, vec![], modules);
            builder.finish()
        },
    )
    .await;

    assert!(matches!(
        effects.status.unwrap_err().0,
        ExecutionFailureStatus::PackageUpgradeError {
            upgrade_error: PackageUpgradeError::PackageIDDoesNotMatch {
                package_id: _,
                ticket_id: _
            }
        }
    ));
}
