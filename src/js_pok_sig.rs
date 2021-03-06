// Proof of knowledge of signature for signature from 2016 paper, CT-RSA 2016 (eprint 2015/525), section 6.2

use ps_sig::errors::PSError;
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use ps_sig::keys::{Params, Verkey};
use ps_sig::signature::Signature;
use std::collections::{HashMap, HashSet};

use crate::{ate_2_pairing, VerkeyGroup, VerkeyGroupVec, SignatureGroup};

// Implement proof of knowledge of committed values in a vector commitment for `SignatureGroup`

impl_PoK_VC!(
    ProverCommittingOtherGroup,
    ProverCommittedOtherGroup,
    ProofOtherGroup,
    VerkeyGroup,
    VerkeyGroupVec
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaintextMessages {
    pub messages: Vec<String>
}

impl PlaintextMessages {
    pub fn new(
        messages: Vec<String>
    ) -> Self {

        PlaintextMessages {
            messages,
        }
    }

    pub fn to_field_element_vector(&self) -> FieldElementVector {
        let field_elements: Vec<FieldElement> = self.messages
            .iter()
            .map(|f| FieldElement::from_msg_hash(f.as_bytes()))
            .collect::<Vec<FieldElement>>();
        FieldElementVector::from(field_elements)
    }
}

/*
As [Short Randomizable signatures](https://eprint.iacr.org/2015/525), section 6.2 describes, for proving knowledge of a signature, the signature sigma is first randomized and also
transformed into a sequential aggregate signature with extra message t for public key g_tilde (and secret key 1).
1. Say the signature sigma is transformed to sigma_prime = (sigma_prime_1, sigma_prime_2) like step 1 in 6.2
1. The prover then sends sigma_prime and the value J = X_tilde * Y_tilde_1^m1 * Y_tilde_2^m2 * ..... * g_tilde^t and the proof J is formed correctly.
The verifier now checks whether e(sigma_prime_1, J) == e(sigma_prime_2, g_tilde). Since X_tilde is known,
the verifier can send following a modified value J' where J' = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t with the proof of knowledge of elements of J'.
The verifier will then check the pairing e(sigma_prime_1, J'*X_tilde) == e(sigma_prime_2, g_tilde).

To reveal some of the messages from the signature but not all, in above protocol, construct J to be of the hidden values only, the verifier will
then add the revealed values (raised to the respective generators) to get a final J which will then be used in the pairing check.
*/


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JSPoKOfSignatureProof {
    pub sig: Signature,
    pub J: VerkeyGroup,
    pub proof_vc: ProofOtherGroup,
    pub phi: FieldElement,
    pub shared_randomness: SharedRandomness,
    pub target_domain: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedRandomness {
    pub shared_randomness: FieldElementVector,
}

impl SharedRandomness {
    pub fn new(size: usize) -> Self {
        SharedRandomness {
            shared_randomness: FieldElementVector::new(size),
        }
    }

    pub fn random(size: usize) -> Self {
        SharedRandomness {
            shared_randomness: FieldElementVector::random(size),
        }
    }

    pub fn r1_s(&self) -> FieldElement {
        self.shared_randomness[0].clone()
    }

    pub fn r1_gamma(&self) -> FieldElement {
        self.shared_randomness[1].clone()
    }

    pub fn r2(&self) -> FieldElement {
        self.shared_randomness[2].clone()
    }

    pub fn r3(&self) -> FieldElement {
        self.shared_randomness[3].clone()
    }

    pub fn calculate_phi(domain: String, user_secret: String) -> FieldElement {
        FieldElement::from_msg_hash(domain.as_bytes()) * 
            FieldElement::from_msg_hash(user_secret.as_bytes())
    }

    pub fn calculate_verification_phi(&self, domain: &String) -> FieldElement {        
        FieldElement::from_msg_hash(domain.as_bytes()) * self.r1_s()
    }

    pub fn calculate_verification_elgamal_ciphertext_1(&self, params: &Params) -> SignatureGroup {
        &params.g * self.r3()
    }

    pub fn calculate_verification_elgamal_ciphertext_2(&self) -> SignatureGroup {
        // TODO(jsarihan): share g, h somehow
        let g = SignatureGroup::from_msg_hash("test1".as_bytes());
        let h = SignatureGroup::from_msg_hash("test2".as_bytes());

        g * self.r3() + h * self.r1_gamma()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JSPoKOfSignature {
    pub secrets: FieldElementVector,
    pub shared_randomness: SharedRandomness,
    pub sig: Signature,
    pub J: VerkeyGroup,
    pub pok_vc: ProverCommittedOtherGroup,
    pub phi: FieldElement,
    pub target_domain: String,
    pub params: Params,
}

impl JSPoKOfSignature {
    /// Section 6.2 of paper
    pub fn init(
        sig: &Signature,
        vk: &Verkey,
        params: &Params,
        messages: Vec<FieldElement>,
        blindings: Option<&[FieldElement]>,
        revealed_msg_indices: HashSet<usize>,
        target_domain: &str,
    ) -> Result<Self, PSError> {
        Signature::check_verkey_and_messages_compat(messages.as_slice(), vk)?;
        Self::validate_revealed_indices(messages.as_slice(), &revealed_msg_indices)?;

        let blindings = Self::get_blindings(blindings, messages.as_slice(), &revealed_msg_indices)?;

        
        let (t, sigma_prime) = Self::transform_sig(sig);

        let shared_randomness = SharedRandomness::random(4);
        let phi = shared_randomness.calculate_verification_phi(&target_domain.to_string());

        let (exponents, J, committed) = Self::commit_for_pok(messages, blindings, &revealed_msg_indices, t, vk, params);


        Ok(Self {
            secrets: exponents,
            sig: sigma_prime,
            J,
            pok_vc: committed,
            phi,
            shared_randomness,
            target_domain: target_domain.to_string(),
            params: params.clone(),
        })
    }

    /// Return byte representation of public elements so they can be used for challenge computation
    pub fn to_bytes(&self) -> Vec<u8> {
        
        let mut bytes = vec![];
        bytes.append(&mut self.sig.to_bytes()); // signatures
        bytes.append(&mut self.J.to_bytes()); // proof.k 
        bytes.append(&mut self.pok_vc.to_bytes()); // gens + committment
        
        bytes.append(&mut self.phi.to_bytes()); // phi
        let verfication_phi = self.shared_randomness.calculate_verification_phi(&self.target_domain);
        let verification_e1 = self.shared_randomness.calculate_verification_elgamal_ciphertext_1(&self.params);
        let verification_e2 = self.shared_randomness.calculate_verification_elgamal_ciphertext_2();

        bytes.append(&mut verfication_phi.to_bytes());
        bytes.append(&mut verification_e1.to_bytes());
        bytes.append(&mut verification_e2.to_bytes());
        bytes
    }

    pub fn gen_proof(self, challenge: &FieldElement) -> Result<JSPoKOfSignatureProof, PSError> {
        let proof_vc = self.pok_vc.gen_proof(&challenge, self.secrets.as_slice())?;
        Ok(JSPoKOfSignatureProof {
            sig: self.sig,
            J: self.J,
            proof_vc,
            phi: self.phi,
            shared_randomness: self.shared_randomness,
            target_domain: self.target_domain,
        })
    }

    pub(crate) fn validate_revealed_indices(messages: &[FieldElement],
                                            revealed_msg_indices: &HashSet<usize>) -> Result<(), PSError> {
        for idx in revealed_msg_indices {
            if *idx >= messages.len() {
                return Err(PSError::GeneralError {
                    msg: format!("Index {} should be less than {}", idx, messages.len()),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn get_blindings<'a>(blindings: Option<&'a [FieldElement]>, messages: &[FieldElement],
                                revealed_msg_indices: &HashSet<usize>) -> Result<Vec<Option<&'a FieldElement>>, PSError> {
        let mut blindings = match blindings {
            Some(b) => {
                if (messages.len() - revealed_msg_indices.len()) != b.len() {
                    return Err(PSError::GeneralError {
                        msg: format!(
                            "No of blindings {} not equal to number of hidden messages {}",
                            b.len(),
                            (messages.len() - revealed_msg_indices.len())
                        ),
                    });
                }
                b.iter().map(Some).collect()
            }
            None => (0..(messages.len() - revealed_msg_indices.len()))
                .map(|_| None)
                .collect::<Vec<Option<&'a FieldElement>>>(),
        };

        // Choose blinding for g_tilde randomly
        blindings.insert(0, None);
        Ok(blindings)
    }

    /// Transform signature to an aggregate signature on (messages, t)
    pub(crate) fn transform_sig(sig: &Signature) -> (FieldElement, Signature) {
        let r = FieldElement::random();
        let t = FieldElement::random();

        // Transform signature to an aggregate signature on (messages, t)
        let sigma_prime_1 = &sig.sigma_1 * &r;
        let sigma_prime_2 = (&sig.sigma_2 + (&sig.sigma_1 * &t)) * &r;

        (t, Signature {
            sigma_1: sigma_prime_1,
            sigma_2: sigma_prime_2,
        })
    }

    pub(crate) fn commit_for_pok(messages: Vec<FieldElement>, mut blindings: Vec<Option<&FieldElement>>, revealed_msg_indices: &HashSet<usize>,
                                 t: FieldElement, vk: &Verkey, params: &Params) -> (FieldElementVector, VerkeyGroup, ProverCommittedOtherGroup) {
        // +1 for `t`
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msg_indices.len() + 2;
        let mut bases = VerkeyGroupVec::with_capacity(hidden_msg_count);
        let mut exponents = FieldElementVector::with_capacity(hidden_msg_count);
        bases.push(params.g_tilde.clone());
        exponents.push(t);
        for (i, msg) in messages.into_iter().enumerate() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
            exponents.push(msg);
        }

        // Prove knowledge of m_1, m_2, ... for all hidden m_i and t in J = Y_tilde_1^m_1 * Y_tilde_2^m_2 * ..... * g_tilde^t
        let J = bases.multi_scalar_mul_const_time(&exponents).unwrap();

        // For proving knowledge of messages in J.
        let mut committing = ProverCommittingOtherGroup::new();
        for b in bases.as_slice() {
            committing.commit(b, blindings.remove(0));
        }
        let committed = committing.finish();

        (exponents, J, committed)
    }
}

impl JSPoKOfSignatureProof {
    /// Return bytes that need to be hashed for generating challenge. Since the message only requires
    /// commitment to "non-revealed" messages of signature, generators of only those messages are
    /// to be considered for challenge creation.
    /// Takes bytes of the randomized signature, the "commitment" to non-revealed messages (J) and the
    /// generators and the commitment to randomness used in the proof of knowledge of "non-revealed" messages.
    pub fn get_bytes_for_challenge(
        &self,
        revealed_msg_indices: HashSet<usize>,
        vk: &Verkey,
        params: &Params,
    ) -> Vec<u8> {
        // Calculate b(sig || J || gg || prod(yy) || vc || v_phi || v_e1 || v_e2)
        let mut bytes = vec![];
        bytes.append(&mut self.sig.to_bytes());
        bytes.append(&mut self.J.to_bytes());
        bytes.append(&mut params.g_tilde.to_bytes());


        for i in 0..vk.Y_tilde.len() {
            if revealed_msg_indices.contains(&i) {
                continue;
            }
            let mut b = vk.Y_tilde[i].to_bytes();
            bytes.append(&mut b);
        }
        bytes.append(&mut self.proof_vc.commitment.to_bytes());

        let verfication_phi = self.shared_randomness.calculate_verification_phi(&self.target_domain);
        let verification_e1 = self.shared_randomness.calculate_verification_elgamal_ciphertext_1(params);
        let verification_e2 = self.shared_randomness.calculate_verification_elgamal_ciphertext_2();

        bytes.append(&mut self.phi.to_bytes()); // phi
        bytes.append(&mut verfication_phi.to_bytes());
        bytes.append(&mut verification_e1.to_bytes());
        bytes.append(&mut verification_e2.to_bytes());

        bytes
    }

    /// Get the response from post-challenge phase of the Sigma protocol for the given message index `msg_idx`.
    /// Used when comparing message equality
    pub fn get_resp_for_message(&self, msg_idx: usize) -> Result<FieldElement, PSError> {
        // 1 element in self.proof_vc.responses is reserved for the random `t`
        if msg_idx >= (self.proof_vc.responses.len() - 1) {
            return Err(PSError::GeneralError {
                msg: format!(
                    "Message index was given {} but should be less than {}",
                    msg_idx,
                    self.proof_vc.responses.len() - 1
                ),
            });
        }
        // 1 added to the index, since 0th index is reserved for randomization (`t`)
        Ok(self.proof_vc.responses[1 + msg_idx].clone())
    }

    pub fn verify(
        &self,
        vk: &Verkey,
        params: &Params,
        revealed_msgs: HashMap<usize, FieldElement>,
        challenge: &FieldElement,
    ) -> Result<bool, PSError> {
        if self.sig.is_identity() {
            return Ok(false);
        }
        // +1 for `t`
        // +1 for V_E2
        let hidden_msg_count = vk.Y_tilde.len() - revealed_msgs.len() + 1;
        let mut bases = VerkeyGroupVec::with_capacity(hidden_msg_count);
        bases.push(params.g_tilde.clone());
        for i in 0..vk.Y_tilde.len() {
            if revealed_msgs.contains_key(&i) {
                continue;
            }
            bases.push(vk.Y_tilde[i].clone());
        }
        if !self.proof_vc.verify(bases.as_slice(), &self.J, challenge)? {
            return Ok(false);
        }
        // e(sigma_prime_1, J*X_tilde) == e(sigma_prime_2, g_tilde) => e(sigma_prime_1, J*X_tilde) * e(sigma_prime_2^-1, g_tilde) == 1
        let mut j;
        let J = if revealed_msgs.is_empty() {
            &self.J
        } else {
            j = self.J.clone();
            let mut b = VerkeyGroupVec::with_capacity(revealed_msgs.len());
            let mut e = FieldElementVector::with_capacity(revealed_msgs.len());
            for (i, m) in revealed_msgs {
                b.push(vk.Y_tilde[i].clone());
                e.push(m.clone());
            }
            j += b.multi_scalar_mul_var_time(&e).unwrap();
            &j
        };


        // e(sigma_1, (J + &X_tilde)) == e(sigma_2, g_tilde) => e(sigma_1, (J + &X_tilde)) * e(-sigma_2, g_tilde) == 1
        // Slight optimization possible by precomputing inverse of g_tilde and storing to avoid inverse of sig.sigma_2
        let res = ate_2_pairing(
            &self.sig.sigma_1,
            &(J + &vk.X_tilde),
            &(-&self.sig.sigma_2),
            &params.g_tilde,
        );
        Ok(res.is_one())
    }
}



#[cfg(test)]
mod tests {
    use crate::SignatureGroupVec;
use super::*;
    // For benchmarking
    use ps_sig::keys::keygen;
    use std::time::{Duration, Instant};

    impl_PoK_VC!(
        ProverCommittingSignatureGroup,
        ProverCommittedSignatureGroup,
        ProofSignatureGroup,
        SignatureGroup,
        SignatureGroupVec
    );

    #[test]
    fn test_PoK_sig() {
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen(count_msgs, &params);

        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();
        assert!(sig.verify(msgs.clone(), &vk, &params).unwrap());

        let pok = JSPoKOfSignature::init(&sig, &vk, &params, msgs.clone(), None, HashSet::new(), "hello.com").unwrap();

        let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

        let proof = pok.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(HashSet::new(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        assert!(proof.verify(&vk, &params, HashMap::new(), &chal_verifier).unwrap());

        // PoK with supplied blindings
        let blindings = FieldElementVector::random(count_msgs);
        let pok_1 = JSPoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs,
            Some(blindings.as_slice()),
            HashSet::new(),
            "hello.com",
        )
        .unwrap();
        let chal_prover = FieldElement::from_msg_hash(&pok_1.to_bytes());
        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let chal_bytes = proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof_1
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn test_PoK_sig_reveal_messages() {
        let count_msgs = 10;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen(count_msgs, &params);

        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();

        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();
        assert!(sig.verify(msgs.clone(), &vk, &params).unwrap());

        let mut revealed_msg_indices = HashSet::new();
        revealed_msg_indices.insert(2);
        revealed_msg_indices.insert(4);
        revealed_msg_indices.insert(9);

        let pok = JSPoKOfSignature::init(
            &sig,
            &vk,
            &params,
            msgs.clone(),
            None,
            revealed_msg_indices.clone(),
            "hello.com",
        )
        .unwrap();

        let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

        let proof = pok.gen_proof(&chal_prover).unwrap();

        let mut revealed_msgs = HashMap::new();
        for i in &revealed_msg_indices {
            revealed_msgs.insert(i.clone(), msgs[*i].clone());
        }
        // The verifier generates the challenge on its own.
        let chal_bytes = proof.get_bytes_for_challenge(revealed_msg_indices.clone(), &vk, &params);
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);
        assert!(proof
            .verify(&vk, &params, revealed_msgs.clone(), &chal_verifier)
            .unwrap());

        // Reveal wrong message
        let mut revealed_msgs_1 = revealed_msgs.clone();
        revealed_msgs_1.insert(2, FieldElement::random());
        assert!(!proof.verify(&vk, &params, revealed_msgs_1.clone(), &chal_verifier).unwrap());
    }

    #[test]
    fn test_PoK_multiple_sigs() {
        // Prove knowledge of multiple signatures together (using the same challenge)
        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen(count_msgs, &params);

        let msgs_1 = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let sig_1 = Signature::new(msgs_1.as_slice(), &sk, &params).unwrap();
        assert!(sig_1.verify(msgs_1.clone(), &vk, &params).unwrap());

        let msgs_2 = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let sig_2 = Signature::new(msgs_2.as_slice(), &sk, &params).unwrap();
        assert!(sig_2.verify(msgs_2.clone(), &vk, &params).unwrap());

        let pok_1 =
            JSPoKOfSignature::init(&sig_1, &vk, &params, msgs_1, None, HashSet::new(), "hello.com").unwrap();
        let pok_2 =
            JSPoKOfSignature::init(&sig_2, &vk, &params, msgs_2, None, HashSet::new(), "hello.com").unwrap();

        let mut chal_bytes = vec![];
        chal_bytes.append(&mut pok_1.to_bytes());
        chal_bytes.append(&mut pok_2.to_bytes());

        let chal_prover = FieldElement::from_msg_hash(&chal_bytes);

        let proof_1 = pok_1.gen_proof(&chal_prover).unwrap();
        let proof_2 = pok_2.gen_proof(&chal_prover).unwrap();

        // The verifier generates the challenge on its own.
        let mut chal_bytes = vec![];
        chal_bytes.append(&mut proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        chal_bytes.append(&mut proof_2.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        assert!(proof_1
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
        assert!(proof_2
            .verify(&vk, &params, HashMap::new(), &chal_verifier)
            .unwrap());
    }

    #[test]
    fn test_PoK_multiple_sigs_with_same_msg() {
        // Prove knowledge of multiple signatures and the equality of a specific message under both signatures.
        // Knowledge of 2 signatures and their corresponding messages is being proven.
        // 2nd message in the 1st signature and 5th message in the 2nd signature are to be proven equal without revealing them

        let count_msgs = 5;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen(count_msgs, &params);

        let same_msg = FieldElement::random();
        let mut msgs_1 = (0..count_msgs-1).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        msgs_1.insert(1, same_msg.clone());
        let sig_1 = Signature::new(msgs_1.as_slice(), &sk, &params).unwrap();
        assert!(sig_1.verify(msgs_1.clone(), &vk, &params).unwrap());

        let mut msgs_2 = (0..count_msgs-1).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        msgs_2.insert(4, same_msg.clone());
        let sig_2 = Signature::new(msgs_2.as_slice(), &sk, &params).unwrap();
        assert!(sig_2.verify(msgs_2.clone(), &vk, &params).unwrap());

        // A particular message is same
        assert_eq!(msgs_1[1], msgs_2[4]);

        let same_blinding = FieldElement::random();

        let mut blindings_1 = FieldElementVector::random(count_msgs - 1);
        blindings_1.insert(1, same_blinding.clone());

        let mut blindings_2 = FieldElementVector::random(count_msgs - 1);
        blindings_2.insert(4, same_blinding.clone());

        // Blinding for the same message is kept same
        assert_eq!(blindings_1[1], blindings_2[4]);

        let pok_1 = JSPoKOfSignature::init(
            &sig_1,
            &vk, &params,
            msgs_1,
            Some(blindings_1.as_slice()),
            HashSet::new(),
            "hello.com",
        )
        .unwrap();
        let pok_2 = JSPoKOfSignature::init(
            &sig_2,
            &vk, &params,
            msgs_2,
            Some(blindings_2.as_slice()),
            HashSet::new(),
            "hello.com",
        )
        .unwrap();

        let mut chal_bytes = vec![];
        chal_bytes.append(&mut pok_1.to_bytes());
        chal_bytes.append(&mut pok_2.to_bytes());

        let chal = FieldElement::from_msg_hash(&chal_bytes);

        let proof_1 = pok_1.gen_proof(&chal).unwrap();
        let proof_2 = pok_2.gen_proof(&chal).unwrap();

        // Response for the same message should be same (this check is made by the verifier)
        assert_eq!(
            proof_1.get_resp_for_message(1).unwrap(),
            proof_2.get_resp_for_message(4).unwrap()
        );

        // The verifier generates the challenge on its own.
        // The verifier generates the challenge on its own.
        let mut chal_bytes = vec![];
        chal_bytes.append(&mut proof_1.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        chal_bytes.append(&mut proof_2.get_bytes_for_challenge(HashSet::new(), &vk, &params));
        let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

        assert!(proof_1.verify(&vk, &params, HashMap::new(), &chal_verifier).unwrap());
        assert!(proof_2.verify(&vk, &params, HashMap::new(), &chal_verifier).unwrap());
    }

    #[test]
    fn timing_pok_signature() {
        // Measure time to prove knowledge of signatures, both generation and verification of proof
        let iterations = 100;
        let count_msgs = 10;
        let params = Params::new("test".as_bytes());
        let (sk, vk) = keygen(count_msgs, &params);

        let msgs = (0..count_msgs).map(|_| FieldElement::random()).collect::<Vec<FieldElement>>();
        let sig = Signature::new(msgs.as_slice(), &sk, &params).unwrap();

        let mut total_generating = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..iterations {
            let start = Instant::now();

            let pok =
                JSPoKOfSignature::init(&sig, &vk, &params, msgs.clone(), None, HashSet::new(), "hello.com").unwrap();

            let chal_prover = FieldElement::from_msg_hash(&pok.to_bytes());

            let proof = pok.gen_proof(&chal_prover).unwrap();
            total_generating += start.elapsed();

            let start = Instant::now();
            // The verifier generates the challenge on its own.
            let chal_bytes = proof.get_bytes_for_challenge(HashSet::new(), &vk, &params);
            let chal_verifier = FieldElement::from_msg_hash(&chal_bytes);

            assert!(proof.verify(&vk, &params, HashMap::new(), &chal_verifier).unwrap());

            total_verifying += start.elapsed();
        }

        println!(
            "Time to create {} proofs is {:?}",
            iterations, total_generating
        );
        println!(
            "Time to verify {} proofs is {:?}",
            iterations, total_verifying
        );
    }
}
