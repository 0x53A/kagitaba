//! PIV protocol with replaceable APDU transport. Private keys stay on device.
#![forbid(unsafe_code)]
mod piv;
pub mod usb;
pub use piv::*;
#[cfg(test)]
mod tests;
