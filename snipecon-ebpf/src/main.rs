#![no_std]
#![no_main]

// We use TcContext now instead of SkBuff for modern Aya versions
use aya_ebpf::{macros::classifier, programs::TcContext};

#[classifier]
pub fn snipecon_probe(ctx: TcContext) -> i32 {
    match try_snipecon_probe(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_snipecon_probe(_ctx: TcContext) -> Result<i32, u32> {
    // The kernel is now watching the traffic!
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
