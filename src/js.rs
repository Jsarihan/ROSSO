
use coconut_sig::signature::Params as CParams;

use crate::SignatureGroup;
use crate::amcl_wrapper::group_elem::GroupElement;

/// Utility module to help with JS/WASM interfacing

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Public {
    pub g: SignatureGroup,
    pub h: SignatureGroup,
    pub cparams: CParams,
    pub msg_count: usize,
    pub server_count: usize,
    pub threshold: usize,
}

impl Public {
    pub fn new(msg_count: usize, label: &[u8], threshold: usize, server_count: usize) -> Self {
        let g = SignatureGroup::from_msg_hash(&[label, " : g".as_bytes()].concat());
        let h = SignatureGroup::from_msg_hash(&[label, " : h".as_bytes()].concat());

        let cparams = CParams::new(msg_count, label);
        Public {
            g,
            h,
            cparams,
            server_count,
            msg_count,
            threshold,
        }
    }   
}