#![cfg(feature = "ledger")]

use std::str::FromStr;

use bhwi::{
    Interpreter,
    ledger::{
        GetAppInfoResponse, LedgerCommand, LedgerDisplayAddress, LedgerError, LedgerInterpreter,
        LedgerResponse, LedgerWalletPolicy, Version,
        apdu::{ApduCommand, ApduError},
        store::StoreError,
    },
};
use bitcoin::{
    Address, Amount, Network, PublicKey, ScriptBuf, Transaction, TxIn, TxOut, absolute,
    bip32::DerivationPath,
    hashes::{Hash, sha256},
    hex::{DisplayHex, FromHex},
    psbt::{
        Psbt,
        raw::{Key, ProprietaryKey},
    },
    transaction,
};
use miniscript::descriptor::WalletPolicy;

const A: &str = "[0266a74a/48'/1'/0'/2']tpubDFEXpjxZr3xqdAFQWoDRzo5CaJCc7zFbNV7WzB43oAnLvTSq9Kw8A7iJPWmgJbpCZ4nndgZgjsVb7dr1rnBmYdnmcWz7sfhyvBdhueh5XaX";
const B: &str = "[ffd63c8d/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N";
const PUBKEY: &str = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

struct NativeCommand(LedgerCommand);
impl TryFrom<NativeCommand> for LedgerCommand {
    type Error = LedgerError;
    fn try_from(command: NativeCommand) -> Result<Self, Self::Error> {
        Ok(command.0)
    }
}
type Driver = LedgerInterpreter<NativeCommand, ApduCommand, LedgerResponse, LedgerError>;

fn wallet() -> LedgerWalletPolicy {
    LedgerWalletPolicy::new(
        "single".into(),
        Version::V2,
        WalletPolicy::from_str(&format!("wpkh({A}/<0;1>/*)")).unwrap(),
    )
}
fn start(command: LedgerCommand) -> (Driver, ApduCommand) {
    let mut driver = Driver::default();
    let apdu = driver.start(NativeCommand(command)).unwrap();
    (driver, apdu)
}
fn reply(data: impl AsRef<[u8]>, status: u16) -> Vec<u8> {
    [data.as_ref(), &status.to_be_bytes()].concat()
}
fn delegated(driver: &mut Driver, data: &[u8]) -> Result<ApduCommand, LedgerError> {
    driver
        .exchange(reply(data, 0xe000))
        .map(|command| command.expect("continuation"))
}
fn hash(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}
fn preimage(driver: &mut Driver, data: &[u8]) -> Result<ApduCommand, LedgerError> {
    delegated(driver, &[&[0x40, 0][..], &hash(data)].concat())
}
fn psbt() -> Psbt {
    Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(123),
            script_pubkey: ScriptBuf::new(),
        }],
    })
    .unwrap()
}
fn sign(psbt: Psbt) -> (Driver, ApduCommand) {
    start(LedgerCommand::SignPsbt {
        psbt,
        policy: wallet(),
        hmac: None,
    })
}
fn derive_address(policy: &LedgerWalletPolicy, change: bool, index: u32) -> String {
    policy
        .policy
        .clone()
        .into_descriptor()
        .unwrap()
        .into_single_descriptors()
        .unwrap()[usize::from(change)]
    .at_derivation_index(index)
    .unwrap()
    .address(Network::Testnet)
    .unwrap()
    .to_string()
}
fn address_request(policy: LedgerWalletPolicy, change: bool, index: u32) -> LedgerCommand {
    LedgerCommand::GetWalletAddress {
        address: LedgerDisplayAddress::ByWalletPolicy {
            policy,
            hmac: Some([7; 32]),
            change,
            address_index: index,
            display: true,
        },
    }
}

#[test]
fn ordinary_parsers_keep_lengths_bytes_and_context() {
    let (mut driver, apdu) = start(LedgerCommand::GetAppInfo);
    assert_eq!(apdu.encode(), [0xb0, 1, 0, 0, 0]);
    let data = [
        1, 7, b'B', b'i', b't', b'c', b'o', b'i', b'n', 3, b'2', b'.', b'4', 1, 9, 0xff,
    ];
    assert!(driver.exchange(reply(data, 0x9000)).unwrap().is_none());
    let LedgerResponse::AppInfo(info) = driver.end().unwrap() else {
        panic!("app info")
    };
    assert_eq!(
        (info.app_name.as_str(), info.version.as_str(), info.flags),
        ("Bitcoin", "2.4", vec![9])
    );
    for (data, field) in [
        (vec![], "header"),
        (vec![2], "header"),
        (vec![1], "app name"),
        (vec![1, 0], "version"),
        (vec![1, 0, 0], "flags"),
    ] {
        let (mut driver, _) = start(LedgerCommand::GetAppInfo);
        let Err(LedgerError::UnexpectedResult(bytes, context)) =
            driver.exchange(reply(&data, 0x9000))
        else {
            panic!("decode error")
        };
        assert_eq!(bytes, data);
        assert!(context.contains(field), "{context}");
    }
    assert!(
        GetAppInfoResponse::try_from(vec![1])
            .unwrap_err()
            .contains("failed to parse app name")
    );
    for len in 0..4 {
        let (mut driver, _) = start(LedgerCommand::GetMasterFingerprint);
        assert!(matches!(
            driver.exchange(reply(vec![1; len], 0x9000)),
            Err(LedgerError::UnexpectedResult(_, _))
        ));
    }
    let (mut driver, _) = start(LedgerCommand::GetMasterFingerprint);
    driver.exchange(reply([1, 2, 3, 4, 5], 0x9000)).unwrap();
    assert!(
        matches!(driver.end().unwrap(), LedgerResponse::MasterFingerprint(fp) if fp.as_bytes() == &[1,2,3,4])
    );
    for data in [vec![], vec![1; 64], vec![1; 66], vec![0xff; 65]] {
        let (mut driver, _) = start(LedgerCommand::SignMessage {
            message: b"message".to_vec(),
            path: DerivationPath::master(),
        });
        assert!(
            matches!(driver.exchange(reply(&data, 0x9000)), Err(LedgerError::UnexpectedResult(bytes, context)) if bytes == data && context == "signature compact data")
        );
    }
    let key = bitcoin::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
    let sig = bitcoin::secp256k1::Secp256k1::new()
        .sign_ecdsa(&bitcoin::secp256k1::Message::from_digest([2; 32]), &key);
    let (mut driver, _) = start(LedgerCommand::SignMessage {
        message: b"message".to_vec(),
        path: DerivationPath::master(),
    });
    driver
        .exchange(reply(
            [&[0xff][..], &sig.serialize_compact()].concat(),
            0x9000,
        ))
        .unwrap();
    assert!(
        matches!(driver.end().unwrap(), LedgerResponse::Signature(0xff, returned) if returned == sig)
    );
    let (mut driver, _) = start(LedgerCommand::GetXpub {
        path: DerivationPath::master(),
        display: false,
    });
    assert!(matches!(
        driver.exchange(vec![0x90]),
        Err(LedgerError::Apdu(ApduError::ResponseTooShort))
    ));
}

#[test]
fn addresses_preserve_original_valid_text_and_reject_invalid_strings() {
    let policy = wallet();
    let address = derive_address(&policy, true, 7).to_uppercase();
    assert!(Address::from_str(&address).is_ok());
    let (mut driver, apdu) = start(address_request(policy, true, 7));
    assert_eq!(apdu.ins, 3);
    assert_eq!(&apdu.data[65..], &[1, 0, 0, 0, 7]);
    driver.exchange(reply(&address, 0x9000)).unwrap();
    assert!(matches!(driver.end().unwrap(), LedgerResponse::Address(text) if text == address));
    for data in [b"not an address".to_vec(), vec![0xff], vec![]] {
        let (mut driver, _) = start(address_request(wallet(), false, 0));
        assert!(
            matches!(driver.exchange(reply(&data, 0x9000)), Err(LedgerError::UnexpectedResult(bytes, _)) if bytes == data)
        );
    }
}

#[test]
fn wallet_v1_v2_wire_and_ids_match_recorded_baseline() {
    let cases = [
        (
            "single",
            format!("wpkh({A}/<0;1>/*)"),
            [
                (
                    "010673696e676c650b77706b682840302f2a2a29012d332774fb49b6f0df3ee7a22e38ca95e6d633db059a50e16fbc77e1d68445f7",
                    "9e52ecf36f21e073c3176431ee23b20e59a9f4722d14397ac35c6a66daa899a8",
                ),
                (
                    "020673696e676c650bc8974a0d8bdd29024b2ddb7a7fe8df1d9801b270f4e6c1e7e1011ae39e7c9b00012d332774fb49b6f0df3ee7a22e38ca95e6d633db059a50e16fbc77e1d68445f7",
                    "e51051a6019aa6beb77c010b225d584c19e65dc9e8ac9fc0cd2873397df374c0",
                ),
            ],
        ),
        (
            "multisig",
            format!("wsh(sortedmulti(2,{A}/<0;1>/*,{B}/<0;1>/*))"),
            [
                (
                    "01086d756c74697369671f77736828736f727465646d756c746928322c40302f2a2a2c40312f2a2a2929029654b1195eba5a43a33312132ec2173999288ea721875bcae197c625ef875da3",
                    "c750e9d05976134acd9244747904c02659d38346c07a4e1903095e07fe5317f4",
                ),
                (
                    "02086d756c74697369671fb56c3d5542fa09b3956834a9ff6a1df5c36a38e5b02c63c54b41a9a04403b826029654b1195eba5a43a33312132ec2173999288ea721875bcae197c625ef875da3",
                    "cc52886a6db412999341093ec1b1f3e250c66cd0f8294ea2f68613d0d3651937",
                ),
            ],
        ),
        (
            "taproot-repeated",
            format!(
                "tr({A}/<0;1>/*,{{{{and_v(v:multi_a(1,{B}/<2;3>/*,{A}/<2;3>/*),older(17)),and_v(v:multi_a(1,{B}/<4;5>/*,{A}/<4;5>/*),older(20))}},pk({B}/<0;1>/*)}})"
            ),
            [
                (
                    "0110746170726f6f742d72657065617465647f74722840302f2a2a2c7b7b616e645f7628763a6d756c74695f6128312c40312f3c323b333e2f2a2c40302f3c323b333e2f2a292c6f6c64657228313729292c616e645f7628763a6d756c74695f6128312c40312f3c343b353e2f2a2c40302f3c343b353e2f2a292c6f6c64657228323029297d2c706b2840312f2a2a297d29029654b1195eba5a43a33312132ec2173999288ea721875bcae197c625ef875da3",
                    "1e67c0bfe94de9fa9732869c3d6406c1447ee5e0755a63d9491540e4d4338458",
                ),
                (
                    "0210746170726f6f742d72657065617465647fe683ee322ca74bfd84f59fb1edd7aef48a0b3c63e16196931169359573fc1833029654b1195eba5a43a33312132ec2173999288ea721875bcae197c625ef875da3",
                    "e995b166b824cdf307d770f7f49984388755fba387f0a0aa67f71ffc7b97f6ca",
                ),
            ],
        ),
    ];
    for (name, descriptor, vectors) in cases {
        for (version, (wire, id)) in [Version::V1, Version::V2].into_iter().zip(vectors) {
            let policy = LedgerWalletPolicy::new(
                name.into(),
                version,
                WalletPolicy::from_str(&descriptor).unwrap(),
            );
            let (mut driver, apdu) = start(LedgerCommand::RegisterWallet {
                policy: policy.clone(),
            });
            let wire = Vec::from_hex(wire).unwrap();
            assert_eq!(policy.serialize().unwrap(), wire);
            assert_eq!(policy.id().unwrap().as_hex().to_string(), id);
            assert_eq!(&apdu.data[1..], wire);
            assert_eq!(&preimage(&mut driver, &wire).unwrap().data[2..], wire);
            let (_, address) = start(address_request(policy, false, 0));
            assert_eq!(address.data[1..33].as_hex().to_string(), id);
        }
    }
}

#[test]
fn delegated_errors_and_fragment_queue_keep_bhwi_categories() {
    let policy = LedgerWalletPolicy::new("x".repeat(600), Version::V2, wallet().policy);
    let wire = policy.serialize().unwrap();
    let (mut driver, _) = start(LedgerCommand::RegisterWallet { policy });
    let first = preimage(&mut driver, &wire).unwrap();
    assert_eq!(
        &first.data[..4],
        &[0xfd, wire.len() as u8, (wire.len() >> 8) as u8, 251]
    );
    let mut restored = first.data[4..].to_vec();
    while restored.len() < wire.len() {
        let next = delegated(&mut driver, &[0xa0]).unwrap();
        assert_eq!(next.data[1], 1);
        restored.extend(&next.data[2..]);
    }
    assert_eq!(restored, wire);
    assert!(matches!(
        delegated(&mut driver, &[0xa0]),
        Err(LedgerError::Store(StoreError::UnexpectedQueue))
    ));
    let requests = [
        (vec![], 0),
        (vec![0xff], 1),
        (vec![0x40], 2),
        ([&[0x40, 0][..], &[9; 32]].concat(), 3),
        ([&[0x42][..], &[9; 64]].concat(), 4),
    ];
    for (request, expected) in requests {
        let (mut driver, _) = start(LedgerCommand::RegisterWallet { policy: wallet() });
        let error = delegated(&mut driver, &request).err().unwrap();
        assert!(matches!(
            (expected, error),
            (0, LedgerError::Store(StoreError::EmptyInput))
                | (1, LedgerError::Store(StoreError::UnknownCommand(0xff)))
                | (2, LedgerError::Store(StoreError::UnsupportedRequest(0x40)))
                | (3, LedgerError::Store(StoreError::UnknownHash))
                | (4, LedgerError::Store(StoreError::UnknownMerkleRoot))
        ));
        assert!(driver.end().is_err());
    }
    let (mut driver, _) = start(LedgerCommand::RegisterWallet { policy: wallet() });
    preimage(&mut driver, &wallet().serialize().unwrap()).unwrap();
    assert!(matches!(
        delegated(&mut driver, &[0x41]),
        Err(LedgerError::Store(StoreError::UnsupportedRequest(0x41)))
    ));
}

#[test]
fn psbt_unknown_and_proprietary_fields_are_delegated_and_conflicts_rejected() {
    let mut original = psbt();
    let key = Key {
        type_value: 0x70,
        key: vec![1],
    };
    let proprietary = ProprietaryKey {
        prefix: b"musig".to_vec(),
        subtype: 7,
        key: vec![8],
    };
    original
        .unknown
        .insert(key.clone(), b"global unknown".to_vec());
    original
        .proprietary
        .insert(proprietary.clone(), b"global proprietary".to_vec());
    original.inputs[0]
        .unknown
        .insert(key.clone(), b"input unknown".to_vec());
    original.inputs[0]
        .proprietary
        .insert(proprietary.clone(), b"input proprietary".to_vec());
    original.outputs[0]
        .unknown
        .insert(key, b"output unknown".to_vec());
    original.outputs[0]
        .proprietary
        .insert(proprietary, b"output proprietary".to_vec());
    let (mut driver, _) = sign(original.clone());
    for value in [
        "global unknown",
        "global proprietary",
        "input unknown",
        "input proprietary",
        "output unknown",
        "output proprietary",
    ] {
        let bytes = [&[0][..], value.as_bytes()].concat();
        assert_eq!(&preimage(&mut driver, &bytes).unwrap().data[2..], bytes);
    }
    driver.exchange(reply([], 0x9000)).unwrap();
    assert!(
        matches!(driver.end().unwrap(), LedgerResponse::SignedPsbt(returned) if returned == original)
    );
    for (scope, fields) in [
        (0, vec![2, 3, 4, 5, 0xfb]),
        (1, vec![0x0e, 0x0f, 0x10]),
        (2, vec![3, 4]),
    ] {
        for field in fields {
            let mut original = psbt();
            let key = Key {
                type_value: field,
                key: vec![],
            };
            match scope {
                0 => {
                    original.unknown.insert(key, vec![1]);
                }
                1 => {
                    original.inputs[0].unknown.insert(key, vec![1]);
                }
                _ => {
                    original.outputs[0].unknown.insert(key, vec![1]);
                }
            }
            let mut driver = Driver::default();
            assert!(matches!(
                driver.start(NativeCommand(LedgerCommand::SignPsbt {
                    psbt: original,
                    policy: wallet(),
                    hmac: None
                })),
                Err(LedgerError::InvalidPsbt(_))
            ));
        }
    }
    for input in [true, false] {
        let mut original = psbt();
        if input {
            original.inputs.clear();
        } else {
            original.outputs.clear();
        }
        let mut driver = Driver::default();
        assert!(matches!(
            driver.start(NativeCommand(LedgerCommand::SignPsbt {
                psbt: original,
                policy: wallet(),
                hmac: None
            })),
            Err(LedgerError::InvalidPsbt(_))
        ));
    }
}

fn compact(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => [&[0xfd][..], &value.to_le_bytes()[..2]].concat(),
        0x10000..=0xffff_ffff => [&[0xfe][..], &value.to_le_bytes()[..4]].concat(),
        _ => [&[0xff][..], &value.to_le_bytes()].concat(),
    }
}
fn musig(tag: u64, index: u64) -> Vec<u8> {
    let key = Vec::from_hex(PUBKEY).unwrap();
    [
        compact(tag),
        compact(index),
        vec![0xaa; if tag == 0xffff_ffff { 66 } else { 32 }],
        key.clone(),
        key,
    ]
    .concat()
}
fn yield_result(payloads: &[Vec<u8>]) -> Result<LedgerResponse, LedgerError> {
    let (mut driver, _) = sign(psbt());
    for payload in payloads {
        delegated(&mut driver, &[&[0x10][..], payload].concat())?;
    }
    driver.exchange(reply([], 0x9000))?;
    driver.end()
}
#[test]
fn signatures_insert_ecdsa_and_both_taproot_paths() {
    let public = PublicKey::from_str(PUBKEY).unwrap();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
    let sig = bitcoin::ecdsa::Signature::sighash_all(
        bitcoin::secp256k1::Secp256k1::new()
            .sign_ecdsa(&bitcoin::secp256k1::Message::from_digest([2; 32]), &secret),
    );
    let ecdsa = [&[0, 33][..], &public.to_bytes(), &sig.to_vec()].concat();
    let xonly = &public.to_bytes()[1..];
    let keypath = [&[0, 32][..], xonly, &[0xaa; 64]].concat();
    let scriptpath = [&[0, 64][..], xonly, &[0xbb; 32], &[0xaa; 64]].concat();
    let LedgerResponse::SignedPsbt(returned) = yield_result(&[ecdsa, keypath, scriptpath]).unwrap()
    else {
        panic!("signed PSBT")
    };
    assert_eq!(returned.inputs[0].partial_sigs.get(&public), Some(&sig));
    assert!(returned.inputs[0].tap_key_sig.is_some());
    assert_eq!(returned.inputs[0].tap_script_sigs.len(), 1);
}
#[test]
fn malformed_and_ignored_yields_validate_before_insertion() {
    for tag in [0xffff_ffff, 0xffff_fffe] {
        let valid = musig(tag, 0);
        let LedgerResponse::SignedPsbt(returned) =
            yield_result(std::slice::from_ref(&valid)).unwrap()
        else {
            panic!("PSBT")
        };
        assert_eq!(returned, psbt());
        assert!(matches!(
            yield_result(&[musig(tag, 1)]),
            Err(LedgerError::InvalidPsbt(_))
        ));
        let mut malformed = valid;
        let offset = 5 + 1 + if tag == 0xffff_ffff { 66 } else { 32 };
        malformed[offset..offset + 33].fill(0);
        assert!(matches!(
            yield_result(&[malformed]),
            Err(LedgerError::InvalidPsbt(_))
        ));
    }
    for index in [1, u64::MAX] {
        assert!(matches!(
            yield_result(&[[compact(0x8000_0000), compact(index)].concat()]),
            Err(LedgerError::InvalidPsbt(_))
        ));
    }
    assert!(
        matches!(yield_result(&[[compact(0x8000_0000), vec![0]].concat()]).unwrap(), LedgerResponse::SignedPsbt(returned) if returned == psbt())
    );
    for payload in [
        vec![],
        vec![0xfd],
        vec![0xfe, 0],
        vec![0xff, 0],
        vec![0xfd, 0, 0],
        vec![0xfe, 0xfd, 0, 0, 0],
        vec![0],
        vec![0, 32],
        vec![0, 33, 0],
        [compact(0x8000_0000), vec![0xfd, 0, 0]].concat(),
    ] {
        assert!(matches!(
            yield_result(&[payload]),
            Err(LedgerError::InvalidPsbt(_))
        ));
    }
    let public = Vec::from_hex(PUBKEY).unwrap();
    let out_of_bounds = [&[1, 32][..], &public[1..], &[0xaa; 64]].concat();
    assert!(matches!(
        yield_result(&[out_of_bounds]),
        Err(LedgerError::InvalidPsbt(_))
    ));
}

#[test]
fn message_chunks_and_missing_leaf_use_vendor_delegation() {
    let path: DerivationPath = "m/84'/1'/0'/0/2".parse().unwrap();
    let (mut driver, apdu) = start(LedgerCommand::SignMessage {
        message: vec![5; 65],
        path: path.clone(),
    });
    assert_eq!(apdu.ins, 0x10);
    let mut restored = Vec::new();
    for count in [64, 1] {
        let chunk = [&[0][..], &vec![5; count]].concat();
        restored.extend_from_slice(&preimage(&mut driver, &chunk).unwrap().data[3..]);
    }
    assert_eq!(restored, vec![5; 65]);
    let root = &apdu.data[apdu.data.len() - 32..];
    let missing = [&[0x42][..], root, &[9; 32]].concat();
    assert_eq!(delegated(&mut driver, &missing).unwrap().data, [0, 0]);
    let (mut driver, _) = start(LedgerCommand::GetXpub {
        path,
        display: false,
    });
    assert!(
        matches!(driver.exchange(reply(b"not an xpub", 0x9000)), Err(LedgerError::UnexpectedResult(bytes, context)) if bytes == b"not an xpub" && context == "xpub string")
    );
}

#[test]
fn registration_parser_accepts_tail_and_rejects_short_payloads() {
    for length in [0, 31, 32, 63] {
        let (mut driver, _) = start(LedgerCommand::RegisterWallet { policy: wallet() });
        assert!(
            matches!(driver.exchange(reply(vec![1; length], 0x9000)), Err(LedgerError::UnexpectedResult(bytes, context)) if bytes.len() == length && context == "register wallet: response too short")
        );
    }
    let (mut driver, _) = start(LedgerCommand::RegisterWallet { policy: wallet() });
    let data = [&wallet().id().unwrap()[..], &[7; 32], &[0xff]].concat();
    assert!(driver.exchange(reply(data, 0x9000)).unwrap().is_none());
    assert!(matches!(driver.end().unwrap(), LedgerResponse::WalletHmac(hmac) if hmac == [7;32]));
}
