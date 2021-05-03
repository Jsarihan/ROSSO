use amcl_wrapper::field_elem::{FieldElement};
use amcl_wrapper::group_elem_g2::G2;
use coconut_sig::elgamal_keygen;
use coconut_sig::signature::{Signature, Verkey, transform_to_PS_verkey, transform_to_PS_sig, transform_to_PS_params};
use ps_sig::keys::Verkey as PSVerkey;
use ps_sig::signature as PSSignature;
use std::collections::HashSet;

use crate::js_pok_sig::{JSPoKOfSignature, JSPoKOfSignatureProof};
use crate::js_signature::{JSBlindSignature, JSMessages, JSSignatureRequest, JSSignatureRequestPoK, JSSignatureRequestProof};

use crate::js::Public as PublicParams;

#[derive(Clone, Debug)]
pub struct ElGamalKeys {
    sk: FieldElement,
    pub pk: G2,
}

impl ElGamalKeys {
    pub fn new (param: &G2) -> Self {
        let (sk, pk) = elgamal_keygen!(param);
        ElGamalKeys {
            sk,
            pk
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientIdRequest {
    pub sig_req: JSSignatureRequest, 
    pub sig_req_proof: JSSignatureRequestProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerBlindSignature {
    pub id: usize,
    pub blind_sig: JSBlindSignature,
    pub vk_share: Verkey,
}



#[derive(Clone, Debug)]
pub struct Client {
    public: PublicParams,
    secret: FieldElement,
    pub elg_keys: ElGamalKeys,
    credential: Option<PSSignature::Signature>,
    ps_verkey: Option<PSVerkey>,
}

impl Client {
    pub fn new (public: PublicParams, user_secret: String) -> Self {
        let elg_keys = ElGamalKeys::new(&public.cparams.g);
        Client {
            public,
            secret: FieldElement::from_msg_hash(user_secret.as_bytes()),
            elg_keys,
            credential: None,
            ps_verkey: None,
        }
    }

    pub fn request_id (&self, visible_messages: Vec<String>, hidden_messages: Vec<String>) -> ClientIdRequest {
        let messages = JSMessages::new(visible_messages, hidden_messages);
        let (sig_req, randomness) = JSSignatureRequest::new(messages.clone(), &self.elg_keys.pk, &self.public.cparams);

        // Initiate proof of knowledge of various items of Signature request
        let sig_req_pok = JSSignatureRequestPoK::init(&sig_req,&self.elg_keys.pk, &self.public.cparams);

        // The challenge can include other things also (if proving other predicates)
        let challenge_for_prover = FieldElement::from_msg_hash(&sig_req_pok.to_bytes());

        // Create proof once the challenge is finalized
        let sig_req_proof = sig_req_pok
            .gen_proof(&messages.hashed_hidden, randomness, &self.elg_keys.sk, &challenge_for_prover)
            .unwrap();

        ClientIdRequest {
            sig_req,
            sig_req_proof,
        }
    }

    pub fn verify_signatures (&mut self, mut blinded_sigs: Vec<ServerBlindSignature>) {
        let mut unblinded_sigs = vec![];
        let mut vk_pairs: Vec<(usize, Verkey)> = vec![];
        for _i in 0..self.public.threshold {
            let sbs = blinded_sigs.remove(0);
            vk_pairs.push((sbs.id, sbs.vk_share.clone()));

            // unblind signature
            let unblinded_sig = sbs.blind_sig.unblind(&self.elg_keys.sk);
            unblinded_sigs.push((sbs.id, unblinded_sig));
        }

        let aggr_sig = transform_to_PS_sig(&Signature::aggregate(self.public.threshold, unblinded_sigs));
        self.credential = Some(aggr_sig);

        let aggr_vk = transform_to_PS_verkey(&Verkey::owned_aggregate(
            self.public.threshold,
            vk_pairs
        ));
        self.ps_verkey = Some(aggr_vk);
    }

    pub fn offer_ps_verkey (&self) -> Option<PSVerkey> {
        return self.ps_verkey.clone()
    }

    pub fn aggregate_and_store_signature (mut self, threshold: usize, unblinded_signatures: Vec<(usize, Signature)>) -> Self{
        let aggr_sig = Signature::aggregate(threshold, unblinded_signatures);
        self.credential = Some(transform_to_PS_sig(&aggr_sig));

        self
    }

    pub fn prove_id (&self,
        messages: JSMessages,
        revealed_msg_indices: HashSet<usize>,
        domain: &String,
    ) -> Option<JSPoKOfSignatureProof> {
        if let Some(verkey) = &self.ps_verkey {
            let pok = JSPoKOfSignature::init(
                self.credential.as_ref().unwrap(),
                verkey,
                &transform_to_PS_params(&self.public.cparams),
                messages.all.as_slice().to_vec().clone(),
                None,
                revealed_msg_indices,
                domain,
            )
            .expect("Could not initialize proof of knowledge.");
    
            let chal = FieldElement::from_msg_hash(&pok.to_bytes());
            pok.gen_proof(&chal).ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_client_setup() {
        let threshold = 3;
        let total = 5;
        let msg_count = 6;

        let label = "test";
        let user_secret = String::from("cheese");
        let public_params = PublicParams::new(msg_count, label.as_bytes(), threshold, total);
        let client = Client::new(public_params, user_secret);

        let visible_strings = vec!["these", "are", "all", "visible"];
        let visible_messages = visible_strings.iter().map(|&s| s.to_string()).collect::<Vec<String>>();
        let hidden_strings = vec!["not", "these"];
        let hidden_messages = hidden_strings.iter().map(|&s| s.to_string()).collect::<Vec<String>>();

        client.request_id(visible_messages, hidden_messages);
    }
}