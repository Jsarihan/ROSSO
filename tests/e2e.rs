use coconut_sig::signature::{Verkey};
use std::collections::HashSet;
use thesis::{ttp, d_idp, client, rp, js};
use thesis::client::ServerBlindSignature;
use thesis::js_signature::JSMessages;

#[test]
fn test_get_credential_from_d_idp() {
    // Common setup
    let msg_count = 6;
    let label = "hello";
    let total_server_count = 5;
    let threshold = 1; // >= 3 out of 5 server signatures required

    // Publicly available parameters
    let public_params = js::Public::new(msg_count, &label.as_bytes(), threshold, total_server_count);

    // For RP + issuing credentials
    let domain = String::from("hello.com");

    // TTP Setup
    let ttp = ttp::TrustedThirdParty::new(threshold, total_server_count, &public_params);

    // IdP Setup
    let mut idps: Vec<d_idp::DistributedIdP> = vec![];
    for id in 0..total_server_count {
        let serialized_signer = ttp.serialize_server_i(id).expect("Could not serialize signer");
        idps.push(d_idp::DistributedIdP::from_serialized_signer(&serialized_signer, &public_params))
    }
    assert_eq!(idps.clone().len(), total_server_count);

    // Set up RP
    let rp = rp::RelyingParty::new(domain.clone(), public_params.clone());

    let mut vk_shares: Vec<(usize, Verkey)> = vec![];
    for idp in idps.clone() {
        vk_shares.push(idp.get_id_vk());
    }
    // Get verification key from idps
    let rp = rp.aggregate_and_store_verification_key(vk_shares);

    // Client setup
    let mut client = client::Client::new(public_params.clone(), String::from("my-secret"));

    // Create signature request
    let visible_messages = vec!["food".to_string(); 4];
    let hidden_messages = vec!["topsecret".to_string(); 2];
    let messages = JSMessages::new(visible_messages.clone(), hidden_messages.clone());

    let id_request = client.request_id(visible_messages, hidden_messages);
    let sig_req = id_request.sig_req;
    let sig_req_proof = id_request.sig_req_proof;

    
    let mut blinded_sigs: Vec<ServerBlindSignature> = vec![];
    for idp in idps {
        blinded_sigs.push(idp.verify_and_blind_sign(&sig_req, &sig_req_proof, &client.elg_keys.pk));
    }

    client.verify_signatures(blinded_sigs);
    let pok = client.prove_id(messages, HashSet::new(), &domain).unwrap();
    
    // Verify client id
    let verification = rp.verify_id(pok).unwrap();
    assert_eq!(verification, true)
}