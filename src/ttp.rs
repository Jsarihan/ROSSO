
use coconut_sig::keygen::{trusted_party_SSS_keygen, Signer};

use crate::js::Public as PublicParams;

#[derive(Clone, Debug)]
pub struct TrustedThirdParty {
    signers: Vec<Signer>
}


impl TrustedThirdParty {

    /// Instantiate Trusted Third Party with shared Params
    pub fn new (threshold: usize, total: usize, public: &PublicParams) -> Self {
        // Must include messages for gamma, user_secret, tp
        // Generate params and signing keys
        let (_, _, signers) = trusted_party_SSS_keygen(threshold, total, &public.cparams);

        // Init trusted third party to hold + distribute keys
        TrustedThirdParty {
            signers,
        }
    }

    /// Get serialized id and keys for ith server
    pub fn serialize_server_i (&self, idx: usize) -> Option<String> {
        let signer = self.signers.get(idx)?;
        serde_json::to_string(&signer).ok()
    }

    /// Get serialized id and keys for ith server
    pub fn deserialize_server_i (&self, string: &String) -> Option<Signer> {
        serde_json::from_str(string).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ttp_setup() {
        let threshold = 3;
        let total = 5;
        let msg_count = 6;

        let label = "test";
        let public_params = PublicParams::new(msg_count, label.as_bytes(), threshold, total);

        TrustedThirdParty::new(threshold, total, &public_params);
    }

    #[test]
    fn test_ttp_serialization() {
        let threshold = 3;
        let total = 5;
        let msg_count = 6;

        let label = "test";
        let public_params = PublicParams::new(msg_count, label.as_bytes(), threshold, total);

        let ttp = TrustedThirdParty::new(threshold, total, &public_params);
        let serialized_0 = ttp.serialize_server_i(0).expect("Could not serialize signer");

        
        let server_0: Signer = ttp.deserialize_server_i(&serialized_0).expect("Could not deserialize server");
        assert_eq!(server_0.id, 1);
    }
}