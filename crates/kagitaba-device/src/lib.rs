//! PIV protocol with replaceable APDU transport. Private keys stay on device.
#![forbid(unsafe_code)]
mod piv;
#[cfg(feature = "usb")]
pub mod usb;
pub use piv::*;
#[cfg(test)]
mod tests;
