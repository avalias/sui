module base_addr::base {
    struct NewStruct<T> {
        field: T
    }

    public fun return_0(): u64 { 1 }

    public fun plus_1(x: u64): u64 { x + 1 }

    fun non_public_fun(y: bool, r: u64): u64 { if (y) 0 else r }

    public fun new_public_fun(y: bool, r: u64): u64 { if (y) 0 else r }
}
