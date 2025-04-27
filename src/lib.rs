#![no_std]

use core::array;

use embedded_io_async::{ErrorType, Read, ReadExactError, Write};
use hash_based_signature::one_time::HashOneTimeSig;
use kem::*;
use rand::Rng;
use sha3::{Digest, digest::typenum::Unsigned};
use slh_dsa::{
    signature::{rand_core::CryptoRngCore, SignerMut}, ParameterSet, Shake128s, Signature, SignatureLen, SigningKey, VerifyingKey
};
use x_wing::{CIPHERTEXT_SIZE, Ciphertext, DecapsulationKey, EncapsulationKey};
#[derive(Clone)]
pub struct SecretIdentity<P: ParameterSet>{
    pub sign: SigningKey<P>,
    pub decaps: DecapsulationKey,
}
// pub trait NukeChainParser: ErrorType {
//     async fn gather<T: Read>(
//         &mut self,
//         val: &mut T,
//     ) -> Result<Option<hash_based_signature::one_time::HashOneTimeVK<sha3::Sha3_256>>, T::Error>
//     where
//         Self::Error: Into<T::Error>;
// }
pub async fn blob_init<T: Write, P: ParameterSet>(
    mut l: &mut T,
    mut ekeys: impl Iterator<Item = (EncapsulationKey, slh_dsa::SigningKey<P>)>,
    mut rng: &mut (dyn CryptoRngCore + '_),
    ss: Option<[u8; 32]>,
) -> Result<[u8; 32], T::Error> {
    let rng = &mut rng;
    let mut ss: [u8; 32] = match ss {
        None => rng.r#gen(),
        Some(a) => a,
    };
    // let mut rss = ss;
    let mut sha = sha3::Sha3_256::default();
    for (e, mut s) in ekeys {
        l.write_all(b"xD").await?;
        let Ok((ct, mut ss2)) = e.encapsulate(rng);
        let d = sha3::Sha3_256::digest(e.as_bytes());
        let r: [u8; 256] = array::from_fn(|_| rng.r#gen());
        let g = (0..)
            .find_map(|n| s.try_sign_with_context(&ss2, &d, Some(&r[0..n])).ok())
            .unwrap();
        for (dest, src) in ss2.iter_mut().zip(ss.iter().cloned()) {
            *dest ^= src;
        }

        l.write_all(&g.to_bytes()).await?;
        let ct = ct.as_bytes();
        l.write_all(&ct).await?;
        l.write_all(&ss2).await?;

        sha.update(&d);
        l.write_all(&d).await?;
    }
    for (dest, src) in ss.iter_mut().zip(sha.finalize().into_iter()) {
        *dest ^= src;
    }
    l.write_all(b"ee").await?;
    Ok((ss))
}
pub async fn blob_fetch<T: Read, P: ParameterSet>(
    t: &mut T,
    d: &DecapsulationKey,
    vk: &VerifyingKey<P>,
    // nuker: &mut impl NukeChainParser<Error: Into<T::Error>>,
) -> Result<Option<[u8; 32]>, ReadExactError<T::Error>> {
    let mut vs = None;
    let mut sha = sha3::Sha3_256::default();
    loop {
        let mut b = [0u8; 2];
        t.read_exact(&mut b).await?;
        match &b {
            // b"nk" => {
            //     let ss = nuker.gather(t).await?;
            //     let x = HashOneTimeSig::read_async(t).await?;
            //     match ss {
            //         Some(a) if a.verify_live(sha.clone(), &x) => {
            //             return Ok(None);
            //         }
            //         _ => {}
            //     };
            // }
            b"xD" => {
                let mut s: hybrid_array::Array<u8, <P as SignatureLen>::SigLen> =
                    Default::default();
                t.read_exact(&mut s).await?;
                let sig = Signature::<P>::from(&s);
                let mut ct = [0u8; CIPHERTEXT_SIZE];
                t.read_exact(&mut ct).await?;
                let mut s = [0u8; 32];
                t.read_exact(&mut s).await?;
                let mut h = [0u8; 32];
                t.read_exact(&mut h).await?;
                sha.update(&h);
                if h[..] == sha3::Sha3_256::digest(d.encapsulation_key().as_bytes())[..]
                    && vk.try_verify_with_context(&s, &h, &sig).is_ok()
                {
                    let d = d.decapsulate(&Ciphertext::from(&ct)).unwrap();
                    for (dest, src) in s.iter_mut().zip(d.iter().cloned()) {
                        *dest ^= src;
                    }
                    vs = Some(s);
                }
            }
            _ => {
                return Ok(vs.map(|mut v| {
                    for (dest, src) in v.iter_mut().zip(sha.finalize().into_iter()) {
                        *dest ^= src;
                    }
                    v
                }));
            }
        }
    }
}
