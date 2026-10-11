//! Direct USB CCID, scoped to the selected Yubico smart-card interface.
use crate::{Error, Piv, Result, Transport};
use nusb::{
    MaybeFuture,
    transfer::{Buffer, Bulk, In, Out},
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
#[derive(Clone, Debug)]
pub struct Device {
    pub info: nusb::DeviceInfo,
    pub interface: u8,
    pub label: String,
    pub serial: Option<String>,
}
pub fn devices() -> Result<Vec<Device>> {
    let mut out = Vec::new();
    for info in nusb::list_devices().wait().map_err(|_| Error::Usb)? {
        if info.vendor_id() != 0x1050 {
            continue;
        }
        for intf in info.interfaces() {
            if intf.class() == 0x0b {
                let mut device = Device {
                    label: String::new(),
                    serial: None,
                    interface: intf.interface_number(),
                    info: info.clone(),
                };
                // YubiKeys commonly omit the USB serial descriptor. Read the
                // canonical decimal serial through PIV instead; never send a PIN.
                device.serial = Usb::open(&device)
                    .and_then(Piv::new)
                    .and_then(|mut card| card.serial_number())
                    .ok()
                    .map(|serial| serial.to_string());
                device.label = format!(
                    "{} — {}",
                    info.product_string().unwrap_or("YubiKey"),
                    device
                        .serial
                        .as_deref()
                        .unwrap_or("serial unavailable (USB busy or inaccessible)")
                );
                out.push(device);
            }
        }
    }
    Ok(out)
}
pub struct Usb {
    input: nusb::Endpoint<Bulk, In>,
    output: nusb::Endpoint<Bulk, Out>,
    sequence: u8,
}
impl Usb {
    pub fn open(device: &Device) -> Result<Self> {
        let dev = device.info.open().wait().map_err(|_| Error::Usb)?;
        let config = dev.active_configuration().map_err(|_| Error::Usb)?;
        let interface = config
            .interface_alt_settings()
            .find(|i| i.interface_number() == device.interface && i.alternate_setting() == 0)
            .ok_or(Error::Protocol)?;
        let endpoints: Vec<_> = interface
            .endpoints()
            .filter(|e| e.transfer_type() == nusb::descriptors::TransferType::Bulk)
            .map(|e| e.address())
            .collect();
        let input = *endpoints
            .iter()
            .find(|v| **v & 0x80 != 0)
            .ok_or(Error::Protocol)?;
        let output = *endpoints
            .iter()
            .find(|v| **v & 0x80 == 0)
            .ok_or(Error::Protocol)?;
        let intf = dev
            .claim_interface(device.interface)
            .wait()
            .map_err(|_| Error::Usb)?;
        let mut out = Self {
            input: intf.endpoint(input).map_err(|_| Error::Usb)?,
            output: intf.endpoint(output).map_err(|_| Error::Usb)?,
            sequence: 0,
        };
        out.message(0x62, &[])?;
        Ok(out)
    }
    fn message(&mut self, kind: u8, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if data.len() > 4096 {
            return Err(Error::Protocol);
        }
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        let mut request = vec![kind];
        request.extend_from_slice(&(data.len() as u32).to_le_bytes());
        request.extend_from_slice(&[0, seq, 0, 0, 0]);
        request.extend_from_slice(data);
        let mut sent = self
            .output
            .transfer_blocking(request.into(), Duration::from_secs(5));
        sent.buffer.fill(0);
        sent.into_result().map_err(|_| Error::Usb)?;
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Usb)?;
            let mut received = self.input.transfer_blocking(Buffer::new(8192), remaining);
            let response = Zeroizing::new(received.buffer.to_vec());
            received.buffer.fill(0);
            received.into_result().map_err(|_| Error::Usb)?;
            if let Some(payload) = decode_response(&response, seq)? {
                return Ok(Zeroizing::new(payload.to_vec()));
            }
        }
    }
}
impl Transport for Usb {
    fn exchange(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.message(0x6f, command)
    }
}
impl Drop for Usb {
    fn drop(&mut self) {
        // Reset volatile card authentication before releasing the CCID interface.
        // Best effort: an unplugged device cannot acknowledge power-off.
        let request = vec![0x63, 0, 0, 0, 0, 0, self.sequence, 0, 0, 0];
        let mut sent = self
            .output
            .transfer_blocking(request.into(), Duration::from_millis(250));
        sent.buffer.fill(0);
        if sent.status.is_ok() {
            let mut response = self
                .input
                .transfer_blocking(Buffer::new(8192), Duration::from_millis(250));
            response.buffer.fill(0);
        }
    }
}
fn decode_response(bytes: &[u8], sequence: u8) -> Result<Option<&[u8]>> {
    if bytes.len() < 10 || bytes[0] != 0x80 || bytes[5] != 0 || bytes[6] != sequence {
        return Err(Error::Protocol);
    }
    let size = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
    if size > 8192 || size + 10 != bytes.len() {
        return Err(Error::Protocol);
    }
    match bytes[7] & 0xc0 {
        0x80 => Ok(None),
        0 if bytes[7] & 3 == 0 && bytes[9] == 0 => Ok(Some(&bytes[10..])),
        _ => Err(Error::Protocol),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ccid_rejects_malformed_and_misrouted_responses() {
        let good = [0x80, 2, 0, 0, 0, 0, 5, 0, 0, 0, 0x90, 0];
        assert_eq!(decode_response(&good, 5).unwrap().unwrap(), [0x90, 0]);
        for n in 0..good.len() {
            assert!(decode_response(&good[..n], 5).is_err());
        }
        assert!(decode_response(&good, 6).is_err());
        let mut chain = good;
        chain[9] = 1;
        assert!(decode_response(&chain, 5).is_err());
    }
}
