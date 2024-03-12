use zeroize::Zeroize;

#[derive(Debug, Clone, Default, Zeroize)]
pub struct RsaPrivateKey {
    pub p: rsa::BigUint,
    pub q: rsa::BigUint,
    pub d: rsa::BigUint,
    pub u: rsa::BigUint,
}

impl RsaPrivateKey {
    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let m = rsa::BigUint::from_bytes_be(data);
        let n = &self.p * &self.q;
        m.modpow(&self.d, &n).to_bytes_be()
    }
}

pub(crate) fn get_mpi(data: &[u8]) -> (rsa::BigUint, &[u8]) {
    let len = (usize::from(data[0]) * 256 + usize::from(data[1]) + 7) >> 3;
    let (head, tail) = data[2..].split_at(len);
    (rsa::BigUint::from_bytes_be(head), tail)
}

pub(crate) fn get_rsa_key(data: &[u8]) -> (rsa::BigUint, rsa::BigUint, rsa::BigUint, rsa::BigUint) {
    let (p, data) = get_mpi(data);
    let (q, data) = get_mpi(data);
    let (d, data) = get_mpi(data);
    let (u, _) = get_mpi(data);
    (p, q, d, u)
}
