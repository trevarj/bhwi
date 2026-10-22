//! Ledger OS application-opening requests.

use bitcoin::Network;

use super::apdu::ApduCommand;

// https://github.com/LedgerHQ/ledger-live/blob/5a0a1aa5dc183116839851b79bceb6704f1de4b9/libs/ledger-live-common/src/hw/openApp.ts#L3
/// Creates an application-open request, using `Bitcoin Test` for every non-mainnet network.
pub fn open_app(network: Network) -> ApduCommand {
    ApduCommand {
        cla: 0xe0,
        ins: 0xd8,
        p1: 0x00,
        p2: 0x00,
        data: if network == Network::Bitcoin {
            b"Bitcoin".to_vec()
        } else {
            b"Bitcoin Test".to_vec()
        },
    }
}
