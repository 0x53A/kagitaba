//! Android application boundary. Secret crypto remains in Rust.
//! Only the JNI symbol export requires an unsafe attribute; no raw JNI pointers
//! are dereferenced by this crate. The JNI library owns that audited boundary.
#![deny(unsafe_op_in_unsafe_fn)]

mod piv;
mod store;

use jni::{
    JNIEnv,
    objects::{JByteArray, JClass},
    sys::jbyteArray,
};
use zeroize::Zeroizing;

/// Native-testable boundary; errors never contain request values or credentials.
pub fn execute(request: &[u8], random: Vec<u8>) -> Result<String, &'static str> {
    if request.len() > 96 * 1024 * 1024 || random.len() > 1024 * 1024 {
        return Err("Request exceeds limits");
    }
    let text = std::str::from_utf8(request).map_err(|_| "Invalid request")?;
    let parsed = store::Secret(serde_json::from_str(text).map_err(|_| "Invalid request")?);
    if parsed.0["identity"]
        .as_str()
        .is_some_and(|s| s.starts_with("piv:"))
    {
        return piv::execute(text, random);
    }
    if parsed.0["op"]
        .as_str()
        .is_some_and(|op| op.starts_with("store_"))
    {
        store::execute(text, random)
    } else {
        futures::executor::block_on(kagitaba_browser::execute(text, random))
            .map_err(|_| "Invalid or unsupported cryptographic operation")
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_kagitaba_android_NativeBridge_openPiv(
    mut env: JNIEnv,
    _class: JClass,
    request: JByteArray,
    connection: jni::objects::JObject,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if env
            .get_array_length(&request)
            .map_err(|_| "Invalid PIV request")?
            > 2 * 1024 * 1024
        {
            return Err("Invalid PIV request");
        }
        let bytes = Zeroizing::new(
            env.convert_byte_array(&request)
                .map_err(|_| "Invalid PIV request")?,
        );
        piv::open(
            &mut env,
            connection,
            std::str::from_utf8(&bytes).map_err(|_| "Invalid PIV request")?,
        )
    }))
    .unwrap_or(Err("PIV operation failed"));
    match result {
        Ok(value) => env
            .byte_array_from_slice(value.as_bytes())
            .map(|a| a.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(message) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            std::ptr::null_mut()
        }
    }
}

/// Called exclusively by the private native bridge in the Android application.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_kagitaba_android_NativeBridge_execute(
    mut env: JNIEnv,
    _class: JClass,
    request: JByteArray,
    random: JByteArray,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if env
            .get_array_length(&request)
            .map_err(|_| "Invalid request")?
            > 96 * 1024 * 1024
            || env
                .get_array_length(&random)
                .map_err(|_| "Invalid randomness")?
                > 1024 * 1024
        {
            return Err("Request exceeds limits");
        }
        let bytes = Zeroizing::new(
            env.convert_byte_array(&request)
                .map_err(|_| "Invalid request")?,
        );
        let entropy = env
            .convert_byte_array(&random)
            .map_err(|_| "Invalid randomness")?;
        execute(&bytes, entropy).map(Zeroizing::new)
    }))
    .unwrap_or(Err("Native operation failed"));
    match result {
        Ok(value) => env
            .byte_array_from_slice(value.as_bytes())
            .map(|array| array.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(message) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            std::ptr::null_mut()
        }
    }
}
