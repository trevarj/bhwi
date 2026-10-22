//! Ledger Bitcoin application commands, wallet policies, and delegated data requests.
//!
//! Common signing requires Ledger device context even when its HMAC is absent.
//! Common descriptor display also requires that context; management and backup
//! commands are unsupported, and opening an application requires a network.

pub mod command;
pub mod store;

pub mod apdu;
pub mod wallet;

use ledger_bitcoin_client::{
    command as vendor_command,
    interpreter::{ClientCommandInterpreter, InterpreterError},
    protocol,
    wallet::WalletPolicy as VendorWalletPolicy,
};

use apdu::{ApduCommand, ApduError, ApduResponse, StatusWord};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::ecdsa::Signature;
use store::StoreError;
pub use wallet::{AddressType, LedgerWalletPolicy, Version, WalletError, singlesig_wallet_policy};

use crate::Interpreter;
use crate::device::DeviceId;

/// Ledger USB vendor and firmware usage page, with the default Speculos endpoint.
pub const LEDGER_DEVICE_ID: DeviceId = DeviceId::new(0x2c97)
    .with_usage_page(0xffa0)
    .with_emulator_path("tcp:127.0.0.1:9999");

/// Errors in Ledger command preparation and interpretation.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// Missing command context or an unsupported common operation.
    #[error("missing command info: {0}")]
    MissingCommandInfo(
        /// Missing context or unsupported-operation description.
        &'static str,
    ),

    /// An operation ended without a result.
    #[error("no error or result returned")]
    NoErrorOrResult,

    /// APDU decoding failure.
    #[error("APDU error")]
    Apdu(
        /// APDU decoder error.
        #[from]
        ApduError,
    ),

    /// Failure answering a delegated data request.
    #[error("store error")]
    Store(
        /// Delegated-store error.
        #[from]
        StoreError,
    ),

    /// Wallet policy encoding failure.
    #[error("wallet error: {0}")]
    Wallet(
        /// Wallet policy error.
        #[from]
        WalletError,
    ),

    /// A command interrupted without usable delegated state.
    #[error("operation interrupted")]
    Interrupted,

    /// Unexpected response bytes and their operation context.
    #[error("unexpected result for {1}: {0:x?}")]
    UnexpectedResult(
        /// Unexpected response bytes.
        Vec<u8>,
        /// Operation context.
        String,
    ),

    /// An unsupported address-display request.
    #[error("unsupported display address: {0}")]
    UnsupportedDisplayAddress(
        /// Unsupported-display description.
        String,
    ),

    /// Failure opening the selected Bitcoin application, with response bytes.
    #[error("failed to open app: {0:x?}")]
    FailedToOpenApp(
        /// Application-open response bytes.
        Vec<u8>,
    ),

    /// A failing status word and the operation it answered.
    #[error("{1} failed: status {0:?} ({:#06x})", *.0 as u16)]
    Status(StatusWord, &'static str),

    /// A status word saying the Bitcoin app is not open or ready.
    #[error("{1} failed, the Bitcoin app is not ready: status {0:?} ({:#06x})", *.0 as u16)]
    AppNotReady(StatusWord, &'static str),

    /// Invalid PSBT data or yielded signing result.
    #[error("invalid psbt: {0}")]
    InvalidPsbt(
        /// Invalid PSBT or signature description.
        String,
    ),

    /// User cancellation reported by the application.
    #[error("action canceled by the user")]
    UserCancelled(StatusWord),
}

/// Upstream HWI's Ledger `cancels` list: 0x6982 and 0x6985 are user
/// cancellations rather than protocol failures.
fn is_cancel(status_word: StatusWord) -> bool {
    matches!(
        status_word,
        StatusWord::Deny | StatusWord::SecurityStatusNotSatisfied | StatusWord::UserRefusedOnDevice
    )
}

impl LedgerError {
    /// Creates an error retaining response bytes and operation context.
    pub fn unexpected_result(data: Vec<u8>, context: impl Into<String>) -> Self {
        LedgerError::UnexpectedResult(data, context.into())
    }
}

/// A Ledger Bitcoin application command interpreted without transport I/O.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LedgerCommand {
    /// Opens `Bitcoin` for mainnet or `Bitcoin Test` for any other network.
    OpenApp(
        /// Network selecting the mainnet or test application.
        Network,
    ),
    /// Requests the running application's name, version, and flags.
    GetAppInfo,
    /// Requests the active wallet's master fingerprint.
    GetMasterFingerprint,
    /// Requests an extended public key.
    GetXpub {
        /// Key derivation path.
        path: DerivationPath,
        /// Whether to ask for confirmation on the device.
        display: bool,
    },
    /// Requests or displays a wallet address.
    GetWalletAddress {
        /// Path-derived or explicit wallet-policy address request.
        address: LedgerDisplayAddress,
    },
    /// Signs a message at the given key path.
    SignMessage {
        /// Message bytes to sign.
        message: Vec<u8>,
        /// Signing key derivation path.
        path: DerivationPath,
    },
    /// Registers a wallet policy and returns its authentication HMAC.
    RegisterWallet {
        /// Named policy to register.
        policy: LedgerWalletPolicy,
    },
    /// Signs a PSBT under an explicit wallet policy.
    SignPsbt {
        /// PSBT to sign.
        psbt: Psbt,
        /// Policy describing the signing wallet.
        policy: LedgerWalletPolicy,
        /// Registration HMAC, or `None` to send a zero HMAC for a standard policy.
        hmac: Option<[u8; 32]>,
    },
}

/// Ledger-native address request consumed by the interpreter.
///
/// A path request derives the corresponding singlesig wallet policy through
/// Ledger API calls. A policy request carries the exact inputs required by the
/// device's `GET_WALLET_ADDRESS` command.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LedgerDisplayAddress {
    /// A single-key policy inferred from an address path and queried device keys.
    ByPath {
        /// Purpose/coin/account/change/index path, at least five levels deep.
        path: DerivationPath,
        /// Whether to display the address on the device.
        display: bool,
    },
    /// An address derived from an explicit policy and optional registration HMAC.
    ByWalletPolicy {
        /// Wallet policy to use.
        policy: LedgerWalletPolicy,
        /// Registration HMAC, or `None` for a zero HMAC.
        hmac: Option<[u8; 32]>,
        /// Whether to use the change branch.
        change: bool,
        /// Address index within the branch.
        address_index: u32,
        /// Whether to display the address on the device.
        display: bool,
    },
}

/// Parsed response from the `GetAppInfo` APDU command.
///
/// The raw response format from the device is:
/// - 1 byte: version tag (0x01)
/// - length-prefixed string: app name
/// - length-prefixed string: app version
/// - length-prefixed bytes: state flags
#[derive(Debug, Clone)]
pub struct GetAppInfoResponse {
    /// Running application name.
    pub app_name: String,
    /// Application version string.
    pub version: String,
    /// Application state flag bytes.
    pub flags: Vec<u8>,
}

impl GetAppInfoResponse {
    /// Returns mainnet for the `Bitcoin` application, and testnet for every other name.
    pub fn network(&self) -> Network {
        if self.app_name == "Bitcoin" {
            Network::Bitcoin
        } else {
            Network::Testnet
        }
    }
}

impl TryFrom<Vec<u8>> for GetAppInfoResponse {
    type Error = String;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        parse_app_info(&data)
    }
}

/// A completed Ledger command result.
pub enum LedgerResponse {
    /// Running application information.
    AppInfo(
        /// Running application information.
        GetAppInfoResponse,
    ),
    /// Master fingerprint of the active wallet.
    MasterFingerprint(
        /// Active wallet master fingerprint.
        Fingerprint,
    ),
    /// Message-signature header byte and ECDSA signature.
    Signature(
        /// Device-returned compact signature header.
        u8,
        /// Message signature.
        Signature,
    ),
    /// A terminal outcome without a returned value.
    ///
    /// Signing also returns this for [`StatusWord::SignatureFail`] or
    /// [`StatusWord::ClaNotSupported`]; it does not guarantee success.
    TaskDone,
    /// Extended public key of the requested path.
    Xpub(
        /// Requested extended public key.
        Xpub,
    ),
    /// Encoded Bitcoin address.
    Address(
        /// Encoded address text.
        String,
    ),
    /// Authentication HMAC returned by wallet registration.
    WalletHmac(
        /// Registration authentication token.
        [u8; 32],
    ),
    /// PSBT containing returned signatures.
    SignedPsbt(
        /// Updated PSBT.
        Psbt,
    ),
}

#[derive(Default)]
#[allow(clippy::large_enum_variant)]
enum State {
    #[default]
    New,
    Running {
        command: LedgerCommand,
        store: Option<ClientCommandInterpreter>,
        wallet: Option<VendorWalletPolicy>,
    },
    GetWalletAddress(GetWalletAddressStep),
    ValidateRegistration {
        hmac: [u8; 32],
        policy: VendorWalletPolicy,
        store: ClientCommandInterpreter,
    },
    Finished(LedgerResponse),
}

enum GetWalletAddressStep {
    Fingerprint {
        path: DerivationPath,
        display: bool,
    },
    Xpub {
        path: DerivationPath,
        fingerprint: Fingerprint,
        display: bool,
    },
    WalletAddress {
        store: ClientCommandInterpreter,
        policy: VendorWalletPolicy,
        change: bool,
        address_index: u32,
    },
}

/// A sans-I/O Ledger interpreter answering application data requests from a delegated store.
pub struct LedgerInterpreter<C, T, R, E> {
    state: State,
    _marker: std::marker::PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for LedgerInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::default(),
            _marker: std::marker::PhantomData,
        }
    }
}

fn from_vendor(command: ledger_bitcoin_client::apdu::APDUCommand) -> ApduCommand {
    ApduCommand {
        cla: command.cla,
        ins: command.ins,
        p1: command.p1,
        p2: command.p2,
        data: command.data,
    }
}

fn parse_app_info(data: &[u8]) -> Result<GetAppInfoResponse, String> {
    let (app_name, version, flags) =
        protocol::parse_version(data).map_err(|error| match error {
            protocol::ResponseError::Decode { field, source } => {
                let field = if field == "name" { "app name" } else { field };
                format!("failed to parse {field}: {source}")
            }
            _ => format!(
                "invalid version response header: expected 0x01, got {:02x}",
                data.first().copied().unwrap_or(0)
            ),
        })?;
    Ok(GetAppInfoResponse {
        app_name,
        version,
        flags,
    })
}

fn store_error(error: InterpreterError) -> LedgerError {
    LedgerError::Store(match error {
        InterpreterError::EmptyInput => StoreError::EmptyInput,
        InterpreterError::UnknownCommand(command) => StoreError::UnknownCommand(command),
        InterpreterError::UnsupportedRequest(command) => StoreError::UnsupportedRequest(command),
        InterpreterError::InvalidIndexOrSize => StoreError::InvalidIndexOrSize,
        InterpreterError::UnknownHash => StoreError::UnknownHash,
        InterpreterError::UnknownMerkleRoot => StoreError::UnknownMerkleRoot,
        InterpreterError::UnexpectedQueue => StoreError::UnexpectedQueue,
    })
}

fn apply_vendor_signature(psbt: &mut Psbt, yielded: &[u8]) -> Result<(), LedgerError> {
    let (index, object) = protocol::parse_sign_psbt_yielded(yielded)
        .map_err(|_| LedgerError::InvalidPsbt("invalid partial signature yield".into()))?;
    // Bounds-check even objects whose signatures this consumer does not insert.
    if index >= psbt.inputs.len() {
        return Err(LedgerError::InvalidPsbt(format!(
            "invalid input index {index}"
        )));
    }
    if let protocol::SignPsbtYieldedObject::Partial(signature) = object {
        ledger_bitcoin_client::psbt::apply_partial_signature(psbt, index, signature).map_err(
            |error| LedgerError::InvalidPsbt(format!("invalid input index {}", error.input_index)),
        )?;
    }
    Ok(())
}

fn verify_address(
    policy: &VendorWalletPolicy,
    change: bool,
    address_index: u32,
    data: Vec<u8>,
    context: &'static str,
) -> Result<String, LedgerError> {
    let address = match protocol::parse_wallet_address(&data) {
        Ok(address) => address,
        Err(_) => return Err(LedgerError::unexpected_result(data, context)),
    };
    if let Err(error) = protocol::check_address(policy, change, address_index, &address) {
        return Err(LedgerError::unexpected_result(
            data,
            format!("{context}: {error}"),
        ));
    }
    String::from_utf8(data)
        .map_err(|error| LedgerError::unexpected_result(error.into_bytes(), context))
}
impl<C, T, R, E> Interpreter for LedgerInterpreter<C, T, R, E>
where
    C: TryInto<LedgerCommand, Error = LedgerError>,
    T: From<ApduCommand>,
    R: From<LedgerResponse>,
    E: From<LedgerError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: Self::Command) -> Result<Self::Transmit, Self::Error> {
        let command: LedgerCommand = command.try_into()?;
        let mut wallet = None;
        let (transmit, store) = match &command {
            LedgerCommand::GetAppInfo => (from_vendor(vendor_command::get_version()), None),
            LedgerCommand::GetMasterFingerprint => {
                (from_vendor(vendor_command::get_master_fingerprint()), None)
            }
            LedgerCommand::GetXpub { path, display } => (
                from_vendor(vendor_command::get_extended_pubkey(path, *display)),
                None,
            ),
            LedgerCommand::OpenApp(network) => (command::open_app(*network), None),
            LedgerCommand::SignMessage { message, path } => {
                let (command, store) = protocol::prepare_sign_message(message, path);
                (from_vendor(command), Some(store))
            }
            LedgerCommand::GetWalletAddress { address } => match address {
                LedgerDisplayAddress::ByPath { path, display } => {
                    self.state = State::GetWalletAddress(GetWalletAddressStep::Fingerprint {
                        path: path.clone(),
                        display: *display,
                    });
                    return Ok(Self::Transmit::from(from_vendor(
                        vendor_command::get_master_fingerprint(),
                    )));
                }
                LedgerDisplayAddress::ByWalletPolicy {
                    policy,
                    hmac,
                    change,
                    address_index,
                    display,
                } => {
                    let policy = policy.to_vendor().map_err(LedgerError::from)?;
                    let transmit = from_vendor(vendor_command::get_wallet_address(
                        &policy,
                        hmac.as_ref(),
                        *change,
                        *address_index,
                        *display,
                    ));
                    let store = ClientCommandInterpreter::for_wallet(&policy);
                    self.state = State::GetWalletAddress(GetWalletAddressStep::WalletAddress {
                        store,
                        policy,
                        change: *change,
                        address_index: *address_index,
                    });
                    return Ok(Self::Transmit::from(transmit));
                }
            },
            LedgerCommand::RegisterWallet { policy } => {
                let policy = policy.to_vendor().map_err(LedgerError::from)?;
                let command = from_vendor(vendor_command::register_wallet(&policy));
                let store = ClientCommandInterpreter::for_wallet(&policy);
                wallet = Some(policy);
                (command, Some(store))
            }
            LedgerCommand::SignPsbt { psbt, policy, hmac } => {
                let policy = policy.to_vendor().map_err(LedgerError::from)?;
                let (command, store) = protocol::prepare_sign_psbt(psbt, &policy, hmac.as_ref())
                    .map_err(|error| {
                        LedgerError::InvalidPsbt(format!("could not prepare PSBT: {error:?}"))
                    })?;
                (from_vendor(command), Some(store))
            }
        };
        self.state = State::Running {
            command,
            store,
            wallet,
        };
        Ok(Self::Transmit::from(transmit))
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<Self::Transmit>, Self::Error> {
        // Consume pending state even if APDU framing or its status is malformed.
        let state = std::mem::take(&mut self.state);
        let res = ApduResponse::try_from(data).map_err(LedgerError::from)?;
        let (next_state, result) = match state {
            State::GetWalletAddress(GetWalletAddressStep::Fingerprint { path, display }) => {
                if res.status_word != StatusWord::OK {
                    return Err(LedgerError::Status(
                        res.status_word,
                        "display address: master fingerprint",
                    )
                    .into());
                }
                let fingerprint = protocol::parse_master_fingerprint(&res.data).map_err(|_| {
                    LedgerError::unexpected_result(res.data, "display address: master fingerprint")
                })?;
                let children: Vec<_> = path.as_ref().to_vec();
                if children.len() < 5 {
                    return Err(LedgerError::UnsupportedDisplayAddress(
                        "Ledger requires a full 5-level derivation path (e.g. m/84'/0'/0'/0/0)"
                            .into(),
                    )
                    .into());
                }
                let account_path = DerivationPath::from(children[..3].to_vec());
                let cmd = Self::Transmit::from(from_vendor(vendor_command::get_extended_pubkey(
                    &account_path,
                    false,
                )));
                (
                    State::GetWalletAddress(GetWalletAddressStep::Xpub {
                        path,
                        fingerprint,
                        display,
                    }),
                    Some(cmd),
                )
            }
            State::GetWalletAddress(GetWalletAddressStep::Xpub {
                path,
                fingerprint,
                display,
            }) => {
                if res.status_word != StatusWord::OK {
                    return Err(
                        LedgerError::Status(res.status_word, "display address: xpub").into(),
                    );
                }
                let xpub = protocol::parse_extended_pubkey(&res.data).map_err(|_| {
                    LedgerError::unexpected_result(res.data, "display address: xpub")
                })?;
                let children: Vec<_> = path.as_ref().to_vec();
                let change =
                    children[3] == bitcoin::bip32::ChildNumber::from_normal_idx(1).unwrap();
                let address_index = u32::from(children[4]);
                let policy =
                    singlesig_wallet_policy(&path, fingerprint, xpub).map_err(LedgerError::from)?;
                let ledger_policy = LedgerWalletPolicy::new(String::new(), Version::V2, policy);
                let policy = ledger_policy.to_vendor().map_err(LedgerError::from)?;
                let store = ClientCommandInterpreter::for_wallet(&policy);
                let cmd = Self::Transmit::from(from_vendor(vendor_command::get_wallet_address(
                    &policy,
                    None,
                    change,
                    address_index,
                    display,
                )));
                (
                    State::GetWalletAddress(GetWalletAddressStep::WalletAddress {
                        store,
                        policy,
                        change,
                        address_index,
                    }),
                    Some(cmd),
                )
            }
            State::GetWalletAddress(GetWalletAddressStep::WalletAddress {
                mut store,
                policy,
                change,
                address_index,
            }) => {
                if is_cancel(res.status_word) {
                    return Err(LedgerError::UserCancelled(res.status_word).into());
                } else if res.status_word == StatusWord::InterruptedExecution {
                    let transmit = store.execute(res.data).map_err(store_error)?;
                    let cmd = Self::Transmit::from(from_vendor(
                        vendor_command::continue_interrupted(transmit),
                    ));
                    self.state = State::GetWalletAddress(GetWalletAddressStep::WalletAddress {
                        store,
                        policy,
                        change,
                        address_index,
                    });
                    return Ok(Some(cmd));
                } else if res.status_word != StatusWord::OK {
                    return Err(LedgerError::Status(res.status_word, "display address").into());
                } else {
                    let address = verify_address(
                        &policy,
                        change,
                        address_index,
                        res.data,
                        "display address",
                    )?;
                    (State::Finished(LedgerResponse::Address(address)), None)
                }
            }
            State::ValidateRegistration {
                hmac,
                policy,
                mut store,
            } => {
                if is_cancel(res.status_word) {
                    return Err(LedgerError::UserCancelled(res.status_word).into());
                }
                if res.status_word == StatusWord::InterruptedExecution {
                    let transmit = store.execute(res.data).map_err(store_error)?;
                    self.state = State::ValidateRegistration {
                        hmac,
                        policy,
                        store,
                    };
                    return Ok(Some(Self::Transmit::from(from_vendor(
                        vendor_command::continue_interrupted(transmit),
                    ))));
                }
                if res.status_word != StatusWord::OK {
                    return Err(LedgerError::Status(
                        res.status_word,
                        "register wallet: address verification",
                    )
                    .into());
                }
                verify_address(
                    &policy,
                    false,
                    0,
                    res.data,
                    "register wallet: address verification",
                )?;
                (State::Finished(LedgerResponse::WalletHmac(hmac)), None)
            }
            State::Running {
                mut store,
                command,
                wallet,
            } => {
                if res.status_word == StatusWord::InterruptedExecution {
                    if let Some(ref mut s) = store {
                        let transmit = s.execute(res.data).map_err(store_error)?;
                        let cmd = Self::Transmit::from(from_vendor(
                            vendor_command::continue_interrupted(transmit),
                        ));
                        self.state = State::Running {
                            store,
                            command,
                            wallet,
                        };
                        return Ok(Some(cmd));
                    } else {
                        return Err(LedgerError::Interrupted.into());
                    }
                }
                match command {
                    LedgerCommand::GetAppInfo => {
                        if res.status_word != StatusWord::OK {
                            return Err(
                                LedgerError::AppNotReady(res.status_word, "get version").into()
                            );
                        }
                        let response = parse_app_info(&res.data)
                            .map_err(|e| LedgerError::unexpected_result(res.data, e))?;
                        (State::Finished(LedgerResponse::AppInfo(response)), None)
                    }
                    LedgerCommand::GetMasterFingerprint => {
                        if res.status_word != StatusWord::OK {
                            return Err(
                                LedgerError::Status(res.status_word, "master fingerprint").into()
                            );
                        }
                        let fingerprint =
                            protocol::parse_master_fingerprint(&res.data).map_err(|_| {
                                LedgerError::unexpected_result(
                                    res.data,
                                    "master fingerprint response",
                                )
                            })?;
                        (
                            State::Finished(LedgerResponse::MasterFingerprint(fingerprint)),
                            None,
                        )
                    }
                    LedgerCommand::GetXpub {
                        ref path,
                        display: false,
                    } if res.status_word == StatusWord::NotSupported => {
                        // Ledger rejects non-standard derivation paths when the xpub is
                        // requested silently. As in Python HWI's `get_pubkey_at_path`, retry
                        // with display enabled so the user can approve the unusual path.
                        let retry = LedgerCommand::GetXpub {
                            path: path.clone(),
                            display: true,
                        };
                        let transmit = Self::Transmit::from(from_vendor(
                            vendor_command::get_extended_pubkey(path, true),
                        ));
                        self.state = State::Running {
                            store: None,
                            command: retry,
                            wallet: None,
                        };
                        return Ok(Some(transmit));
                    }
                    LedgerCommand::GetXpub { display, .. } => {
                        if display && is_cancel(res.status_word) {
                            return Err(LedgerError::UserCancelled(res.status_word).into());
                        }
                        if res.status_word != StatusWord::OK {
                            return Err(LedgerError::Status(
                                res.status_word,
                                "get extended pubkey",
                            )
                            .into());
                        }
                        let xpub = protocol::parse_extended_pubkey(&res.data)
                            .map_err(|_| LedgerError::unexpected_result(res.data, "xpub string"))?;
                        (State::Finished(LedgerResponse::Xpub(xpub)), None)
                    }
                    LedgerCommand::OpenApp(..) => {
                        if is_cancel(res.status_word) {
                            return Err(LedgerError::UserCancelled(res.status_word).into());
                        }
                        if matches!(
                            res.status_word,
                            StatusWord::OK | StatusWord::ClaNotSupported
                        ) {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        } else {
                            return Err(
                                LedgerError::AppNotReady(res.status_word, "open app").into()
                            );
                        }
                    }
                    LedgerCommand::SignMessage { .. } => match res.status_word {
                        status if is_cancel(status) => {
                            return Err(LedgerError::UserCancelled(status).into());
                        }
                        StatusWord::ClaNotSupported | StatusWord::SignatureFail => {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        }
                        StatusWord::OK => {
                            let (header, sig) = protocol::parse_message_signature(&res.data)
                                .map_err(|_| {
                                    LedgerError::unexpected_result(
                                        res.data,
                                        "signature compact data",
                                    )
                                })?;
                            (
                                State::Finished(LedgerResponse::Signature(header, sig)),
                                None,
                            )
                        }
                        status => {
                            return Err(LedgerError::Status(status, "sign message").into());
                        }
                    },
                    LedgerCommand::GetWalletAddress { .. } => {
                        return Err(LedgerError::MissingCommandInfo("address state").into());
                    }
                    LedgerCommand::RegisterWallet { .. } => {
                        if is_cancel(res.status_word) {
                            return Err(LedgerError::UserCancelled(res.status_word).into());
                        }
                        if res.status_word != StatusWord::OK {
                            return Err(
                                LedgerError::Status(res.status_word, "register wallet").into()
                            );
                        }
                        let (_, hmac) =
                            protocol::parse_wallet_registration(&res.data).map_err(|_| {
                                LedgerError::unexpected_result(
                                    res.data,
                                    "register wallet: response too short",
                                )
                            })?;
                        let policy = wallet
                            .ok_or(LedgerError::MissingCommandInfo("register wallet policy"))?;
                        let store = store.ok_or(LedgerError::Interrupted)?;
                        let transmit =
                            Self::Transmit::from(from_vendor(vendor_command::get_wallet_address(
                                &policy,
                                Some(&hmac),
                                false,
                                0,
                                false,
                            )));
                        (
                            State::ValidateRegistration {
                                hmac,
                                policy,
                                store,
                            },
                            Some(transmit),
                        )
                    }
                    LedgerCommand::SignPsbt { mut psbt, .. } => match res.status_word {
                        status if is_cancel(status) => {
                            return Err(LedgerError::UserCancelled(status).into());
                        }
                        StatusWord::ClaNotSupported | StatusWord::SignatureFail => {
                            (State::Finished(LedgerResponse::TaskDone), None)
                        }
                        StatusWord::OK => {
                            let store = store.ok_or(LedgerError::Interrupted)?;
                            for yielded in store.yielded() {
                                apply_vendor_signature(&mut psbt, &yielded)?;
                            }
                            (State::Finished(LedgerResponse::SignedPsbt(psbt)), None)
                        }
                        status => {
                            return Err(LedgerError::Status(status, "sign psbt").into());
                        }
                    },
                }
            }
            State::New => (State::New, None),
            State::Finished(_) => (state, None),
        };
        self.state = next_state;
        Ok(result)
    }

    fn end(self) -> Result<Self::Response, Self::Error> {
        if let State::Finished(res) = self.state {
            Ok(Self::Response::from(res))
        } else {
            Err(LedgerError::NoErrorOrResult.into())
        }
    }
}
