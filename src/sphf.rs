// Let's start slowly, sphf over diffie hellman tuple

use clear_on_drop::clear::Clear;


use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::RngCore;
use rand_os::OsRng;

use std::io;

use sha3::{Digest, Sha3_512};


// Apparently, that's what is called in various dalek examples, so I guess it's useful for now?


// We're going to implem a routine,
// _ for generating a pair of generators *defining the language*
// _ *HPS key generation* (V) to have a public projection key: hp (Group Element)
// and a private hashing key : hk (2 scalars)
// Original CS02 definition uses 2 different algorithms,
// but weird people (me), stated that non degenerate cases can do both at once
// _ *generate a word in the Language* (P): word is a pair of group elements
// while the associated witness wit is a scalar (discrete logarithm)
// _  on one hand *hash_hps* runs the verifier hashing algorithm with hk, and word
// _ *projhash* runs the prover projective hashing algorithm with hp, and w
// hopefully the returned values (1 group element each) match.


fn define_language()->(EdwardsPoint,EdwardsPoint){
    // Generates two random points on the curve, whose respective DL is unknown...
    println!("Generating a pair of group elements");
    let mut csprng = OsRng::new().unwrap();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let g=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);

    csprng.fill_bytes(&mut bytes);
    let h=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);
    (g,h)
}

fn proj_kg(base_gen:(EdwardsPoint,EdwardsPoint))->((Scalar,Scalar),EdwardsPoint){
    println!("Generates a pair of hashing keys (hk, hp)");
    let mut csprng = OsRng::new().unwrap();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let lg=clamp_scalar(bytes);  // random scalar to "check" the computation on g
    csprng.fill_bytes(&mut bytes);
    let lh=clamp_scalar(bytes); // random scalar to "check" the computation on h

    let hp=lg * base_gen.0 + lh * base_gen.1;
    ((lg,lh),hp)
}

fn generate_word(base_gen:(EdwardsPoint,EdwardsPoint))->(Scalar,(EdwardsPoint,EdwardsPoint)){
    println!("Generate a witness and a Word");
    let mut csprng = OsRng::new().unwrap();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let w=clamp_scalar(bytes);

    let word=(w*base_gen.0, w*base_gen.1);
    (w,word)
}

fn hash_hps(hk:(Scalar,Scalar),word:(EdwardsPoint,EdwardsPoint))->EdwardsPoint{
    println!("Computes the verifier hash as the scalar product between the hk and the word");
    hk.0 * word.0 + hk.1 * word.1
}

fn proj_hash(hp:EdwardsPoint,w:Scalar)->EdwardsPoint{
    println!("Computes the prover projected has as the scalar product between the witness and the projection key");
    w*hp
}


// Starting the CS Part.

fn define_language_cs()->(EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint){
    // Generates 5 random points
    println!("Generating a pair of group elements");
    let mut csprng = OsRng::new().unwrap();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let g=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);

    csprng.fill_bytes(&mut bytes);
    let h=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);

    csprng.fill_bytes(&mut bytes);
    let f=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);

    csprng.fill_bytes(&mut bytes);
    let c=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);

    csprng.fill_bytes(&mut bytes);
    let d=ED25519_BASEPOINT_POINT *clamp_scalar(bytes);

    (g,h,f,c,d)
}

fn proj_kg_cs(base_gen:(EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint))->((Scalar,Scalar,Scalar,Scalar,Scalar),(EdwardsPoint,EdwardsPoint)){
    println!("Generates a pair of hashing keys (hk, hp)");
    let mut csprng = OsRng::new().unwrap();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let lg=clamp_scalar(bytes);  // random scalar to "check" the computation on g
    csprng.fill_bytes(&mut bytes);
    let lh=clamp_scalar(bytes); // random scalar to "check" the computation on h
    csprng.fill_bytes(&mut bytes);
    let lf=clamp_scalar(bytes); // random scalar to "check" the computation on f
    csprng.fill_bytes(&mut bytes);
    let lc=clamp_scalar(bytes); // random scalar to "check" the computation on c and d
    csprng.fill_bytes(&mut bytes);
    let lgg=clamp_scalar(bytes); // random scalar to "check" the computation on g again {Trick to get a KV on CS. BBCPV14}

    let hpa = lg * base_gen.0 + lh * base_gen.1 + lf * base_gen.2  + lc * base_gen.3;
    let hpb= lgg * base_gen.0 + lc * base_gen.4;
    ((lg,lh,lf,lc,lgg),(hpa,hpb))
}

fn generate_word_cs(base_gen:(EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint))->(Scalar,(EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint)){
    println!("Generate a witness and a Word");
    let mut csprng = OsRng::new().unwrap();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let w=clamp_scalar(bytes);

    let a=clamp_scalar([0u8; 32]); //berk
    let mut word=(w*base_gen.0, w*base_gen.1, w*base_gen.2, w*(base_gen.3 +a*base_gen.4));
    // write input message

    let res = hash_to_scal(word.1);
    word.3=w*(base_gen.3+res*base_gen.4);

    (w,word)
}

fn hash_to_scal(p:EdwardsPoint)->Scalar{
    let mut has = Sha3_512::new();
    has.input(p.compress().to_bytes());
    let mut hash: [u8; 64] = [0u8; 64];
    hash.copy_from_slice(has.result().as_slice());
    let mut digest: [u8; 32] = [0u8; 32];
    digest.copy_from_slice(&hash[..32]);

    Scalar::from_bits(digest)
}

fn hash_hps_cs(hk:(Scalar,Scalar,Scalar,Scalar,Scalar),word:(EdwardsPoint,EdwardsPoint,EdwardsPoint,EdwardsPoint))->EdwardsPoint{
    println!("Computes the verifier hash as the scalar product between the hk and the word");
    let res = hash_to_scal(word.1);
    (hk.0 + res * hk.4) * word.0 + hk.1 * word.1 + hk.2 * word.2 + hk.3*word.3
}

fn proj_hash_cs(hp:(EdwardsPoint,EdwardsPoint),w:Scalar,res:Scalar)->EdwardsPoint{
    println!("Computes the prover projected has as the scalar product between the witness and the projection key");
    w*(hp.0 + res*hp.1)
}

// Basic equality check:
fn verify_hps(hash:EdwardsPoint,phash:EdwardsPoint) -> bool {
    println!("Are the hash and projected hashes the same?");
    if hash==phash {
        println!("The values match! You are fantastic");
        return true;
    }
    else {
        println!("It fails! Exterminate...");
        return false;
    }
}



// Shamelessly stolen from dalek examples:
fn clamp_scalar(scalar: [u8; 32]) -> Scalar {
    let mut s: [u8; 32] = scalar.clone();

    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;

    Scalar::from_bits(s)
}

#[cfg(test)]
mod test {
    use super::*;

    fn do_sphf_dh_test(should_succeed: bool) -> bool {
        // Generates the base elements of the Diffie Hellman Language (2 points: g and h)
        let base_gen=define_language();

        // Generates the keys. hk : lambda, mu (two scalars), and hp : g^lambda . h^mu (a group elem)
        let (mut hk,hp)=proj_kg(base_gen);

        // Generates a word in L, and it's witness word=(G,H) where G=g^wit, H=h^wit
        let (mut w,mut word)=generate_word(base_gen);

        if ! should_succeed { // Derp the word if we need to fail
            word.1=w*word.1;
        }

        // Prover computes his view of the hash G^lambda . H^mu
        let ha=hash_hps(hk,word);
        hk.clear();
        // Verifier computes his view hp^wit
        let hb=proj_hash(hp,w);
        w.clear();

        // Checking if they have the same view
        return verify_hps(ha,hb);
    }

    #[test]
    fn sphf_dh_success() {
        assert_eq!(do_sphf_dh_test(true), true);
    }

    #[test]
    fn sphf_dh_failure() {
        assert_eq!(do_sphf_dh_test(false), false);
    }

    fn do_sphf_cs_test(should_succeed: bool) -> bool {
        let base_gen=define_language_cs();

        // Generates the keys. hk : lambda, mu (two scalars), and hp : g^lambda . h^mu (a group elem)
        let (mut hk,hp)=proj_kg_cs(base_gen);

        // Generates a word in L, and it's witness word=(G,H) where G=g^wit, H=h^wit
        let (mut w,mut word)=generate_word_cs(base_gen);

        if ! should_succeed { // Derp the word if we need to fail
            word.1=w*word.1;
        }

        // Prover computes his view of the hash G^lambda . H^mu
        let ha=hash_hps_cs(hk,word);
        hk.clear();

        // Verifier computes his view hp^wit
        let res = hash_to_scal(word.1);
        let hb=proj_hash_cs(hp,w,res);
        w.clear();

        // Checking if they have the same view
        return verify_hps(ha,hb);
    }

    #[test]
    fn sphf_cs_success() {
        assert_eq!(do_sphf_cs_test(true), true);
    }

    #[test]
    fn sphf_cs_failure() {
        assert_eq!(do_sphf_cs_test(false), false);
    }
}
