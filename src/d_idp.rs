use amcl_wrapper::field_elem::FieldElement;
use coconut_sig::keygen::Signer;
use coconut_sig::signature::Verkey;
use ps_sig::SignatureGroup;

use crate::client::ServerBlindSignature;
use crate::js_signature::{JSBlindSignature, JSSignatureRequest, JSSignatureRequestProof};
use crate::js::Public as PublicParams;


#[derive(Clone, Debug)]
pub struct DistributedIdP {
    id: usize,
    keys: Signer,
    public: PublicParams,
}

impl DistributedIdP {
    pub fn new (keys: Signer, public: PublicParams) -> Self {
        DistributedIdP {
            id: keys.id,
            keys,
            public,
        }
    }

    pub fn from_serialized_signer (signer: &String, params: &PublicParams) -> Self {
        let keys: Signer = serde_json::from_str(signer).expect("Failed to deserialize signer");
        DistributedIdP::new(keys, params.clone())
    }

    pub fn blind_sign (&self, sig_req: &JSSignatureRequest) -> ServerBlindSignature {
        ServerBlindSignature {
            id: self.id, 
            blind_sig: JSBlindSignature::new(sig_req, &self.keys.sigkey),
            vk_share: self.keys.verkey.clone(),
        }
    }

    pub fn get_id_vk (&self) -> (usize, Verkey) {
        (self.id, self.keys.verkey.clone())
    }

    pub fn verify_and_blind_sign (&self, sig_req: &JSSignatureRequest, sig_req_proof: &JSSignatureRequestProof, elg_pk: &SignatureGroup) -> ServerBlindSignature {
        // Verify siqnature request proof
        let challenge_for_verifier = FieldElement::from_msg_hash(&sig_req_proof.get_bytes_for_challenge(sig_req, &elg_pk, &self.public.cparams));
        assert!(sig_req_proof
            .verify(&sig_req, &elg_pk, &challenge_for_verifier, &self.public.cparams)
            .unwrap());

        // Issue credential share blindly over request
        self.blind_sign(sig_req)
    }
}



