// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module riskman::policy_config {

    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use std::vector as vec;

    const EAdministratorCannotBeSpender : u64 = 0;
    const ENotEnoughApprovers : u64 = 1;
    const ENotOriginalOwnerOfCapability : u64 = 2;

    struct AdministratorCap has key, store {
        id: UID,
        original_owner: address,
    }

    struct SpenderCap has key, store {
        id: UID,
        original_owner: address,
        policy: Policy,
        spent: u64,
    }

    struct ApproverCap has key, store {
        id: UID,
        original_owner: address,
    }

    struct Assets has key {
        id: UID,
        foundation_balance: Balance<SUI>,
    }

    struct Policy has store {
        amount_limit: u64,
        time_limit: u64,
        approvers_num: u64,
    }

    struct RolesRegistry has key, store {
        id: UID,
        administrators: vector<address>,
        spenders: vector<address>,
        approvers: vector<address>
    }

    // ======== Functions =========
    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdministratorCap{id: object::new(ctx), original_owner: tx_context::sender(ctx)}, 
                          tx_context::sender(ctx)
                        );
        transfer::share_object(Assets {
            id: object::new(ctx),
            foundation_balance: balance::zero()
        });
        transfer::share_object(RolesRegistry {
            id: object::new(ctx),
            administrators: vec::singleton(tx_context::sender(ctx)),
            spenders: vec::empty(),
            approvers: vec::empty()
        });
    }

    /// Optional
    // entry fun create_administrator(
    //     _: &AdministratorCap,
    //     reg: &mut RolesRegistry,
    //     recipient: address,
    //     ctx: &mut TxContext,
    // ) {

    // }

    entry fun create_spender(
        admin_cap: &AdministratorCap,
        reg: &mut RolesRegistry,
        recipient: address,
        amount_limit: u64,
        time_limit: u64,
        approvers_num: u64,
        ctx: &mut TxContext,
    ) {
        assert!(admin_cap.original_owner == tx_context::sender(ctx), 2);
        assert!(tx_context::sender(ctx) != recipient, 0);
        assert!(approvers_num <= vec::length(&reg.approvers), 1);
        transfer::transfer(SpenderCap{
                id: object::new(ctx),
                original_owner: recipient,
                policy: Policy {amount_limit, time_limit, approvers_num},
                spent: 0,
            }, recipient
        );
        vec::push_back(&mut reg.spenders, recipient);
    }

    entry fun create_approver(
        admin_cap: &AdministratorCap,
        reg: &mut RolesRegistry,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        assert!(admin_cap.original_owner == tx_context::sender(ctx), 2);
        transfer::transfer(ApproverCap{
                id: object::new(ctx),
                original_owner: recipient,
            }, recipient
        );
        vec::push_back(&mut reg.approvers, recipient);
    }

    entry fun top_up(
        assets: &mut Assets,
        coin: Coin<SUI>,
        _ctx: &mut TxContext,
    ) {
        coin::put(&mut assets.foundation_balance, coin)
    }

    /// TODO
    // entry fun create_policy(
    //     _: &AdministratorCap,
    //     amount_limit: u64,
    //     time_limit: u64,
    // ) {}

    // entry fun delete_administrator(
    //     _: &AdministratorCap,
    //     reg: &mut RolesRegistry
    //     administrator: address,
    //     ctx: &mut TxContext,
    // ) {

    // }

    // entry fun delete_spender(
    //     _: &AdministratorCap,
    //     reg: &mut RolesRegistry
    //     spender: address,
    //     ctx: &mut TxContext,
    // ) {

    // }

    // entry fun delete_approver(
    //     _: &AdministratorCap,
    //     reg: &mut RolesRegistry
    //     approver: address,
    //     ctx: &mut TxContext,
    // ) {

    // }

    public fun get_foundation_balance_mut(
        assets: &mut Assets
    ) : &mut Balance<SUI> {
        &mut assets.foundation_balance
    }

    public fun get_amount_limit(
        spender_cap: &SpenderCap
    ) : u64 {
        spender_cap.policy.amount_limit
    }

    public fun get_amount_spent(
        spender_cap: &SpenderCap
    ) : u64 {
        spender_cap.spent
    }

    public fun get_time_limit(
        spender_cap: &SpenderCap
    ) : u64 {
        spender_cap.policy.time_limit
    }

    public fun get_approvers_num(
        spender_cap: &SpenderCap
    ) : u64 {
        spender_cap.policy.approvers_num
    }

    public fun get_spender_original_owner(
        spender_cap: &SpenderCap
    ) : address {
        spender_cap.original_owner
    }

     public fun get_approver_original_owner(
        approver_cap: &ApproverCap
    ) : address {
        approver_cap.original_owner
    }

    public fun update_spent(
        spender_cap: &mut SpenderCap,
        amount: u64
    ) {
        spender_cap.spent = spender_cap.spent + amount
    }
}