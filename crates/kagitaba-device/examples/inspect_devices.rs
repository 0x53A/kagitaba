//! Read-only discovery check: no PIN, key generation, or credential reads.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let devices = kagitaba_device::usb::devices()?;
    println!("PIV devices: {}", devices.len());
    println!(
        "Readable serials: {}",
        devices.iter().filter(|d| d.serial.is_some()).count()
    );
    Ok(())
}
