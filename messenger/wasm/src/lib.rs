//! Signal's own libsignal protocol (the version ZENOS Messages uses on the PC, v0.105.1), for the browser.
//!
//! One `Device` is one person's device: its identity key, prekeys and sessions. Everything is made and kept on the
//! device; what goes to the relay is the public half of the keys and ciphertext. Binary values cross the boundary
//! as base64, in the same shapes the relay (`relay.js`) and the PC client (`client.js`) already use, so a browser
//! device and a PC talk to each other through the same relay.
//!
//! The clock comes from the page (`now_ms`): `SystemTime::now()` is not available in the browser's WebAssembly.
//! Random numbers come from the browser's `crypto.getRandomValues` (getrandom's `wasm_js` backend).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::executor::block_on;
use libsignal_protocol::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;

type R<T> = Result<T, JsError>;
fn e<E: std::fmt::Display>(x: E) -> JsError { JsError::new(&x.to_string()) }
fn ub(s: &str) -> R<Vec<u8>> { B64.decode(s).map_err(e) }
fn b64(b: &[u8]) -> String { B64.encode(b) }
fn at(now_ms: f64) -> SystemTime { UNIX_EPOCH + Duration::from_millis(now_ms as u64) }
fn dev1() -> DeviceId { DeviceId::new(1).expect("1 is a device id") }

#[derive(Serialize, Deserialize)]
struct Signed { id: u32, #[serde(rename = "pub")] public: String, sig: String }
#[derive(Serialize, Deserialize)]
struct Pre { id: u32, #[serde(rename = "pub")] public: String }
/// A key bundle as the relay keeps it (`POST /keys/:acc`) and hands it out (`GET /keys/:acc`, one prekey).
#[derive(Serialize, Deserialize)]
struct Bundle {
    #[serde(rename = "regId")] reg_id: u32,
    identity: String,
    signed: Signed,
    kyber: Signed,
    #[serde(rename = "preKeys", default, skip_serializing_if = "Option::is_none")] pre_keys: Option<Vec<Pre>>,
    #[serde(rename = "preKey", default)] pre_key: Option<Pre>,
}

#[wasm_bindgen]
pub struct Device { name: String, store: InMemSignalProtocolStore, bundle: String }

#[wasm_bindgen]
impl Device {
    /// A new device for account `name`: identity key, one signed prekey, one Kyber (ML-KEM 1024) prekey and
    /// `prekeys` one-time prekeys.
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, reg_id: u32, prekeys: u32, now_ms: f64) -> R<Device> {
        let mut rng = rand::rng();
        let idkp = IdentityKeyPair::generate(&mut rng);
        let mut store = InMemSignalProtocolStore::new(idkp, reg_id).map_err(e)?;
        let ts = Timestamp::from_epoch_millis(now_ms as u64);
        let skp = KeyPair::generate(&mut rng);
        let ssig = idkp.private_key().calculate_signature(&skp.public_key.serialize(), &mut rng).map_err(e)?;
        let srec = SignedPreKeyRecord::new(1.into(), ts, &skp, &ssig);
        let kkp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let ksig = idkp.private_key().calculate_signature(&kkp.public_key.serialize(), &mut rng).map_err(e)?;
        let krec = KyberPreKeyRecord::new(1.into(), ts, &kkp, &ksig);
        let mut pres = vec![];
        block_on(async {
            store.save_signed_pre_key(1.into(), &srec).await?;
            store.save_kyber_pre_key(1.into(), &krec).await?;
            for i in 0..prekeys {
                let kp = KeyPair::generate(&mut rng);
                store.save_pre_key((100 + i).into(), &PreKeyRecord::new((100 + i).into(), &kp)).await?;
                pres.push(Pre { id: 100 + i, public: b64(&kp.public_key.serialize()) });
            }
            Ok::<(), SignalProtocolError>(())
        }).map_err(e)?;
        let bundle = Bundle {
            reg_id, identity: b64(&idkp.identity_key().serialize()),
            signed: Signed { id: 1, public: b64(&skp.public_key.serialize()), sig: b64(&ssig) },
            kyber: Signed { id: 1, public: b64(&kkp.public_key.serialize()), sig: b64(&ksig) },
            pre_keys: Some(pres), pre_key: None,
        };
        Ok(Device { name, store, bundle: serde_json::to_string(&bundle).map_err(e)? })
    }

    /// The public halves, in the relay's shape (`regId`, `identity`, `signed`, `kyber`, `preKeys`).
    pub fn bundle(&self) -> String { self.bundle.clone() }

    /// The identity key's signature over a request, as the relay checks it ("X-Zenos-Auth").
    pub fn sign(&self, text: &str) -> R<String> {
        let idkp = block_on(self.store.get_identity_key_pair()).map_err(e)?;
        Ok(b64(&idkp.private_key().calculate_signature(text.as_bytes(), &mut rand::rng()).map_err(e)?))
    }

    /// Start a session with `peer` from the bundle the relay handed out (one prekey).
    pub fn start_session(&mut self, peer: String, bundle_json: &str, now_ms: f64) -> R<()> {
        let b: Bundle = serde_json::from_str(bundle_json).map_err(e)?;
        let pre = match &b.pre_key { Some(p) => Some((p.id.into(), PublicKey::deserialize(&ub(&p.public)?).map_err(e)?)), None => None };
        let pb = PreKeyBundle::new(b.reg_id, dev1(), pre, b.signed.id.into(), PublicKey::deserialize(&ub(&b.signed.public)?).map_err(e)?,
            ub(&b.signed.sig)?, b.kyber.id.into(), kem::PublicKey::deserialize(&ub(&b.kyber.public)?).map_err(e)?, ub(&b.kyber.sig)?,
            IdentityKey::decode(&ub(&b.identity)?).map_err(e)?).map_err(e)?;
        let local = ProtocolAddress::new(self.name.clone(), dev1());
        let s = &mut self.store;
        block_on(process_prekey_bundle(&ProtocolAddress::new(peer, dev1()), &local, &mut s.session_store, &mut s.identity_store,
            &pb, at(now_ms), &mut rand::rng())).map_err(e)
    }

    pub fn has_session(&self, peer: String) -> R<bool> {
        Ok(block_on(self.store.load_session(&ProtocolAddress::new(peer, dev1()))).map_err(e)?.is_some())
    }

    /// Sealed sender: the relay sees a mailbox and a size, not who sent it. `cert` is the sender certificate the
    /// relay issued for this account (`POST /cert`).
    pub fn seal(&mut self, peer: String, cert: &str, plaintext: &str, now_ms: f64) -> R<String> {
        let c = SenderCertificate::deserialize(&ub(cert)?).map_err(e)?;
        let s = &mut self.store;
        let out = block_on(sealed_sender_encrypt(&ProtocolAddress::new(peer, dev1()), &c, plaintext.as_bytes(),
            &mut s.session_store, &mut s.identity_store, at(now_ms), &mut rand::rng())).map_err(e)?;
        Ok(b64(&out))
    }

    /// Open a sealed envelope; checks the sender certificate against `trust` (the relay's trust root).
    /// Returns {"sender": account, "text": plaintext}.
    pub fn open(&mut self, trust: &str, envelope: &str, now_ms: f64) -> R<String> {
        let root = PublicKey::deserialize(&ub(trust)?).map_err(e)?;
        let name = self.name.clone();
        let s = &mut self.store;
        let r = block_on(sealed_sender_decrypt(&ub(envelope)?, &root, Timestamp::from_epoch_millis(now_ms as u64), None, name, dev1(),
            &mut s.identity_store, &mut s.session_store, &mut s.pre_key_store, &s.signed_pre_key_store, &mut s.kyber_pre_key_store)).map_err(e)?;
        Ok(serde_json::json!({ "sender": r.sender_uuid, "text": String::from_utf8_lossy(&r.message) }).to_string())
    }
}
