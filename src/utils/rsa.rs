use zeroize::Zeroize;

use crate::{Error, Result};

#[derive(Debug, Clone, Default, Zeroize)]
pub struct RsaPrivateKey {
    pub p: rsa::BigUint,
    pub q: rsa::BigUint,
    pub d: rsa::BigUint,
    pub u: rsa::BigUint,
}

impl RsaPrivateKey {
    pub fn from_mpi_bytes(data: &[u8]) -> Result<Self> {
        let (p, data) = get_mpi(data)?;
        let (q, data) = get_mpi(data)?;
        let (d, data) = get_mpi(data)?;
        let (u, _) = get_mpi(data)?;
        Ok(Self {
            p: rsa::BigUint::from_bytes_be(p),
            q: rsa::BigUint::from_bytes_be(q),
            d: rsa::BigUint::from_bytes_be(d),
            u: rsa::BigUint::from_bytes_be(u),
        })
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let m = rsa::BigUint::from_bytes_be(data);
        decrypt_rsa(&m, &self.p, &self.q, &self.d).to_bytes_be()
    }
}

/// Extracts the bytes (in BE order) of the MPI-formatted number, along with the rest of the data.
pub(crate) fn get_mpi(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let &[fst, snd, ref data @ ..] = data else {
        return Err(Error::InvalidRsaPrivateKeyFormat);
    };
    let len = (usize::from(fst) * 256 + usize::from(snd) + 7) >> 3;
    if len > data.len() {
        return Err(Error::InvalidRsaPrivateKeyFormat);
    }
    Ok(data.split_at(len))
}

pub(crate) fn decrypt_rsa(
    m: &rsa::BigUint,
    p: &rsa::BigUint,
    q: &rsa::BigUint,
    d: &rsa::BigUint,
) -> rsa::BigUint {
    let n = p * q;
    m.modpow(d, &n)
}
