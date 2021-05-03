#![allow(non_snake_case)]

#[cfg(all(feature = "SignatureG1", feature = "SignatureG2"))]
compile_error!("features `SignatureG1` and `SignatureG2` are mutually exclusive");

// Externs
extern crate amcl_wrapper;

#[macro_use]
extern crate ps_sig;

extern crate rand;

#[macro_use]
extern crate failure;

extern crate serde;
#[macro_use]
extern crate serde_derive;

extern crate secret_sharing;

extern crate wasm_bindgen;

// Imports

use ps_sig::{ate_2_pairing, VerkeyGroup, VerkeyGroupVec, SignatureGroup, SignatureGroupVec};
use ps_sig::keys::Verkey as PSVerkey;
use std::collections::HashSet;
use wasm_bindgen::prelude::*;

// Crate Imports

use crate::client::ClientIdRequest;
use crate::client::ServerBlindSignature;
use crate::js_pok_sig::JSPoKOfSignatureProof;
use crate::js_signature::JSMessages;
use crate::js::Public as PublicParams;
use crate::ttp::TrustedThirdParty;


// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Serialization tools
// TODO(jsarihan): move this to separate module

#[wasm_bindgen]
pub struct SerializedTTP {
    params: PublicParams,
    ttp: TrustedThirdParty,
}

#[wasm_bindgen]
impl SerializedTTP {
    pub fn new (msg_count: usize, label: String, threshold: usize, total: usize) -> Self {
        let params = PublicParams::new(msg_count, label.as_bytes(), threshold, total);
        SerializedTTP {
            params: params.clone(),
            ttp: TrustedThirdParty::new(threshold, total, &params),
        }
    }

    pub fn from_public_params (jsparams: String) -> Self {
        let params: PublicParams = serde_json::from_str(&jsparams).unwrap();
        SerializedTTP {
            params: params.clone(),
            ttp: TrustedThirdParty::new(params.threshold, params.server_count, &params),
        }
    }

    pub fn serialize_public_params (&self) -> Option<String> {
        serde_json::to_string(&self.params).ok()
    }

    pub fn serialize_server (&self, idx: usize) -> Option<String> {
        self.ttp.serialize_server_i(idx)
    }
}


#[wasm_bindgen]
pub struct SerializedClient {
    client: client::Client,
    signature_shares: Vec<ServerBlindSignature>,
    messages: Option<JSMessages>,
}

#[wasm_bindgen]
impl SerializedClient {
    pub fn new(jsparams: String, user_secret: String) -> Self {
        let params: PublicParams = serde_json::from_str(&jsparams).unwrap();
        let signature_shares = vec![];
        SerializedClient {
            client: client::Client::new(params, user_secret),
            signature_shares,
            messages: None,
        }
    }

    pub fn serialized_id_request(&mut self, visible: &JsValue, hidden: &JsValue) -> String {
        let visible_msgs: Vec<String> = visible.into_serde().unwrap();
        let hidden_msgs: Vec<String> = hidden.into_serde().unwrap();
        self.messages = Some(JSMessages::new(hidden_msgs.clone(), visible_msgs.clone()));

        let idRequest = self.client.request_id(visible_msgs, hidden_msgs);
        serde_json::to_string(&idRequest).unwrap()
    }

    pub fn deserialize_blind_signature(&mut self, js_sig: String) {
        let blind_sig: ServerBlindSignature = serde_json::from_str(&js_sig).expect("Failed to deserialize blind signature");
        &self.signature_shares.push(blind_sig);
    }

    pub fn verify_signatures(&mut self) {
        &self.client.verify_signatures(self.signature_shares.clone());
    }

    pub fn deserialize_blind_signatures(&mut self, js_sigs: &JsValue) {
        let blind_sigs: Vec<ServerBlindSignature> = js_sigs.into_serde().unwrap();
        &self.client.verify_signatures(blind_sigs);
    }

    pub fn serialized_id_proof(&mut self, domain: String) -> Option<String> {
        // let revealed_msg_indices: HashSet<usize> = js_msg_indices.into_serde().unwrap();
        if let Some(msgs) = self.messages.clone() {
            let proof = &self.client.prove_id(msgs, HashSet::new(), &domain).unwrap();
            serde_json::to_string(&proof).ok()
        } else {
            None
        }
    }

    pub fn serialize_ps_verkey(&self) -> Option<String> {
        let vk = self.client.offer_ps_verkey();
        serde_json::to_string(&vk.unwrap()).ok()
    }
}

#[cfg(tests)]
mod tests {
    
    #[test]
    fn test_serialize_blind_signatures() {
        let msg_count = 6;
        let label = "hello";
        let total_server_count = 5;
        let threshold = 3; // >= 3 out of 5 server signatures required
    
        // Publicly available parameters
        let public_params = js::Public::new(msg_count, &label.as_bytes(), threshold, total_server_count);
        let js_params = serde_json::to_string(public_params);

        let client = SerializedClient::new(js_params, "yo");
        let visible_strings = vec!["these", "are", "all", "visible"];
        let visible_messages = visible_strings.iter().map(|&s| s.to_string()).collect::<Vec<String>>();
        let hidden_strings = vec!["not", "these"];
        let hidden_messages = hidden_strings.iter().map(|&s| s.to_string()).collect::<Vec<String>>();

        let messages = JSMessages::new(visible_messages.clone(), hidden_messages.clone());
    
        let id_request = client.request_id(visible_messages, hidden_messages);
        let mut blinded_sigs: Vec<String> = vec![];

        let ttp = ttp::TrustedThirdParty::new(threshold, total_server_count, &public_params);

        for id in 0..total_server_count {
            let serialized_signer = ttp.serialize_server_i(id).expect("Could not serialize signer");
            idps.push(SerializedDistributedIdP::new(js_params, serialized_signer));
        }

    }
}

#[wasm_bindgen]
pub struct SerializedDistributedIdP {
    idp: d_idp::DistributedIdP,
}

#[wasm_bindgen]
impl SerializedDistributedIdP {
    pub fn new(jsparams: String, signer: String) -> Self {
        let params: PublicParams = serde_json::from_str(&jsparams).unwrap();
        SerializedDistributedIdP {
            idp: d_idp::DistributedIdP::from_serialized_signer(&signer, &params)
        }
    }

    pub fn blind_sign (&self, js_req: String) -> Option<String> {
        let cir: ClientIdRequest = serde_json::from_str(&js_req).unwrap();
        let signed = self.idp.blind_sign(&cir.sig_req);
        serde_json::to_string(&signed).ok()
    }
}

#[wasm_bindgen]
pub struct SerializedRelyingParty {
    rp: rp::RelyingParty,
}

#[wasm_bindgen]
impl SerializedRelyingParty {
    pub fn new (jsparams: String, domain: String) -> Self {
        let params: PublicParams = serde_json::from_str(&jsparams).unwrap();
        SerializedRelyingParty {
            rp: rp::RelyingParty::new(domain, params),
        }
    }

    pub fn set_verification_key (&mut self, jsvk: String) {
        let vk: PSVerkey = serde_json::from_str(&jsvk).unwrap();
        self.rp.set_verification_key(vk);
    }

    pub fn verify_id (
        &self,
        jsproof: String,
    ) -> Option<bool> {
        let id_proof: JSPoKOfSignatureProof = serde_json::from_str(&jsproof).unwrap();
        self.rp.verify_id(id_proof)
    }
}

// Public modules

pub mod ttp;
pub mod client;
pub mod d_idp;
pub mod rp;
pub mod js;
pub mod js_signature;
pub mod js_pok_sig;
