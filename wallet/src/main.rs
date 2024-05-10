use rwcrypto::vdf_checkpoints;
use rwcrypto::SALT_SIZE;
use std::time::Instant;

fn main() {
    let now = Instant::now();
    let vdf = vdf_checkpoints(&[0u8; SALT_SIZE], &[0u8; SALT_SIZE], 15, 0, 1_000_000);
    let elapsed = now.elapsed();

    println!("Elapsed: {:.2?}", elapsed);
    println!("{:?}", vdf);
}
