use amcl_wrapper::field_elem::FieldElement;
use coconut_sig::signature::{Verkey, transform_to_PS_params, transform_to_PS_verkey};
use ps_sig::keys::Verkey as PSVerkey;
use std::collections::{HashMap, HashSet};

use crate::js_pok_sig::JSPoKOfSignatureProof;
use crate::js::Public as PublicParams;


#[derive(Clone, Debug)]
pub struct RelyingParty {
    domain: String,
    vk: Option<PSVerkey>,
    public: PublicParams,
}

impl RelyingParty {
    pub fn new ( domain: String, public: PublicParams) -> Self {
        RelyingParty {
            domain,
            vk: None,
            public,
        }
    }

    pub fn set_verification_key (&mut self, vk: PSVerkey) {
        self.vk = Some(vk);
    }

    pub fn aggregate_and_store_verification_key (mut self, vk_pairs: Vec<(usize, Verkey)>) -> Self {
        let threshold = self.public.threshold;
        let aggr_ps_vk = transform_to_PS_verkey(&Verkey::owned_aggregate(
            threshold,
            vk_pairs
        ));
        self.vk = Some(aggr_ps_vk);

        self
    }

    pub fn verify_id (
        &self,
        id_proof: JSPoKOfSignatureProof,
    ) -> Option<bool> {
        if let Some(ps_vk) = &self.vk {
            let chal_bytes = id_proof.get_bytes_for_challenge(HashSet::new(), ps_vk, &transform_to_PS_params(&self.public.cparams));
            let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
            
            id_proof.verify(&ps_vk, &transform_to_PS_params(&self.public.cparams), HashMap::new(), &chal_verifier).ok()
        } else {
            None
        }
    }
}

#[cfg(tests)]
mod tests {
    #[test]
    fn test_setup_rp() {
        let rp = RelyingParty::new("hello.com");
        assert_eq!(rp.domain, "hello.com");
    }

    fn test_setup_rp() {
        let rp = RelyingParty::new("hello.com");
    }
}