package org.kagitaba.android

/** Fixed diagnostics only. Never forward transport/native input or arbitrary messages. */
internal object WalletErrors {
    val nativeMessages = setOf(
        "Unknown wallet participant",
        "Participant name must be 1–128 characters without surrounding whitespace or control characters.",
        "Invalid wallet request or credential encoding",
        "Unsupported wallet history. Update all clients to a version supporting signed merges.",
        "Wallet history does not include this device's trusted checkpoint. Fetch updates or resolve divergence on your computer; do not reset trust.",
        "These wallets have different origins and cannot be merged.",
        "Wallet history has multiple merge bases. This app cannot resolve it automatically.",
        "Wallet merge has conflicting entry or participant changes. No changes were accepted; resolve the conflict on your computer.",
        "Wallet signature is missing, invalid, or signed by an unauthorized participant. No changes were accepted.",
        "Wallet records are invalid, unsupported, or exceed limits. Update the app if a newer client wrote this wallet.",
        "Wallet storage could not be read or written. Check available device storage and retry.",
        "Wallet working files differ from signed history. Preserve a backup and repair the working copy before saving.",
        "The wallet branch is not selected. Repair the repository before saving.",
        "Another Git operation is using the wallet. Wait for it to finish and retry.",
        "Wallet changed during this operation. Reload and retry; no new update was accepted.",
        "The signing key refused this operation. Unlock the participant and retry.",
        "The wallet destination is not empty. Open the existing wallet or choose an empty destination."
    )
    fun nativeMessage(message: String): String? = message.takeIf { it in nativeMessages }
}
