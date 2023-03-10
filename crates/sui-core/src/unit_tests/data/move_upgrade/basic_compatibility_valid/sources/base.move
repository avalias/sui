module base_addr::base {
    public fun return_0(): u64 { 0 }

    public fun plus_1(x: u64): u64 { x + 1 }

    fun non_public_fun(y: bool): u64 { if (y) 0 else 1 }
}
