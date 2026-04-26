#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::SkBuff};

#[classifier]
pub fn snipecon_probe(ctx: SkBuff) -> i32 {
    match try_snipecon_probe(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_snipecon_probe(_ctx: SkBuff) -> Result<i32, u32> {
    // This is where we will eventually count packets!
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
