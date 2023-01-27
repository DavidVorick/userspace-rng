#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! userspace-random is a rust crate that is intended to provde secure entropy to
//! the caller even if the operating system entropy is not secure.
//! `userspace_rng::Csprng` implements `rand_core::CryptoRng` and
//! `rand_core::RngCore`.
//!
//! Usage:
//!
//! ```rs
//! // Generate an ed25519 key.
//! let mut rng = userspace_rng::Csprng{};
//! let keypair = ed25519_dalek::Keypair::generate(&mut rng);
//!
//! // Generate 32 bytes of randomness.
//! let rand_data = userspace_rng::random256();
//! ```
//!
//! Modern operating systems like Linux, Mac, and Windows will all provide reliable
//! entropy, however more niche operating systems and environments often will
//! provide broken RNGs to the user. This concern is especially relevant to IoT and
//! embedded hardware, where the engineers are deliberately taking as many
//! shortcuts as they can to trim down the size and overhead of the operating
//! system and hardware. The result may be an unintentionally compromised operating
//! system RNG which can put users at risk.
//!
//! This worry has precedent. When Android was newer, a broken RNG in Android put
//! user funds at risk: <https://bitcoin.org/en/alert/2013-08-11-android>
//!
//! To protect users against insecure hardware, we developed a library that
//! generates reliable entropy in userspace. We have constructed the library to
//! ensure that the randomness can only be compromised if both the operating system
//! RNG is broken and also the assumptions made by our library are incorrect. Had
//! the Android wallets used userspace-random to generate their entropy, user funds
//! likely would have been safe despite the flaw in Android itself.
//!
//! This library draws entropy from CPU jitter. Specifically, the number of
//! nanoseconds required to complete a cryptographic hash function has a high
//! amount of variance. My own testing suggested that under normal circumstances
//! the variance is around 100ns with a standard deviation of around 40ns. This
//! suggests that using time elapsed during a cryptographic hashing function as a
//! source of entropy will provide between 4 and 6 bits of entropy per measurement.
//!
//! When the library starts up, it performs 25 milliseconds of hashing, performing
//! a strict minimum of 512 hashing operations total. This theoretically provides
//! more than 2000 bits of entropy, which means there is a comfortable safety
//! margin provided by the library. Even hardware that is more stable and reliable
//! should be producing at least 1/4 bits of entropy per hash operation owing to
//! the natural physical limitations of CPUs.
//!
//! To give some brief intuition: a CPU is a physical device that consumes
//! electricity and produces heat. The speed at which a CPU operates (at least,
//! with our current technology) is surprisingly dependent on factors like voltage
//! and temperature. Further, these factors tend to vary rapidly as a CPU performs
//! computations. Empirical measurements demonstrate that the variance is
//! sufficiently significant to cause material variance in the total execution time
//! of a cryptographic hash operation. Other factors such as background activity by
//! the operating system can also play a role.
//!
//! For fun, this library also incorporates some ideas from the fortuna paper to
//! protect users against an adversary that has the ability to use side channels to
//! compromise the user entropy. In reality, these extra choices are probably not
//! necessary to protect against real-world attackers. Fortuna was designed with a
//! very different threat model in mind than the one we face with this library.
//!
//! Fortuna paper: <https://www.schneier.com/wp-content/uploads/2015/12/fortuna.pdf>

use std::sync::{Mutex, Once};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Error};
use getrandom::getrandom;
use sha2::{Digest, Sha256};

/// Entropy gets added to the backup pool every time the random library is used. Once every 512
/// calls, the backup pool gets merged into the entropy pool to give the entropy pool an extra
/// boost. As long as each call mixes at least 0.25 bits of entropy into the backup pool, any
/// attacker that has compromised the entropy pool will lose all progress once the backup pool is
/// mixed in.
const BACKUP_FREQUENCY: u128 = 512;

/// Shorthand to declare an issue with the system clock.
const CLOCK_ERR: &str = "system clock could not be read";

/// The entire entropy state consists of an entropy pool, a backup pool, and a counter that gets
/// used to determine when the backup pool should be merged into the entropy pool. The counter is
/// also used to prevent race conditions from causing duplicate entropy to be returned.
///
/// The entropy pool is continuously receiving small amounts of new entropy. this protects the
/// entropy pool against side channel attacks that may be trying to learn the state of the entropy
/// pool. if the entropy pool is compromised, the small incremental bits of entropy that get added
/// to it will not be sufficient to let it recover.
///
/// The backup pool will collect a large amount of entropy before being added to the entropy pool
/// by adding large amounts of entropy all at once, we can ensure that a compromised entropy pool
/// can recover.
struct EntropyState {
    entropy_pool: [u8; 32],
    backup_pool: [u8; 32],
    usage_counter: u128,
}

/// All threads use the same entropy state to generate random numbers.
static ENTROPY_STATE: Mutex<EntropyState> = Mutex::new(EntropyState {
    entropy_pool: [0; 32],
    backup_pool: [0; 32],
    usage_counter: 0,
});

/// Protect the initialization function so it only runs once.
static INIT: Once = Once::new();

/// hash is a simple wrapper around the hashing function used by userspace_random.
fn hash(b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b);
    let r = hasher.finalize();
    let mut dest = [0u8; 32];
    dest.copy_from_slice(&r);
    dest
}

/// Fill out the entropy pool and backup pool using entropy from the operating system then add a
/// large amount of runtime entropy by hashing the original entropy repeatedly. Between each hash
/// we grab the current system time and mix it into the entropy pool. The number of nanoseconds
/// required to complete a hash is highly variable, sometimes varying as much as 200 nanoseconds
/// between consecutive calls. this makes the hash timings an excellent source of runtime entropy
fn init() {
    INIT.call_once(|| {
        // get randomness from the operating system. if the call fails we will instead start with
        // an empty array and rely fully on the userspace random call. We panic in debug builds so
        // that the developer knows something is wrong with the call to getrandom.
        let mut base = [0u8; 32];
        let mut backup = [0u8; 32];
        match getrandom(&mut base) {
            Ok(_) => {}
            Err(error) => {
                debug_assert!(false, "unable to get base randomness from OS: {}", error);
            }
        }
        match getrandom(&mut backup) {
            Ok(_) => {}
            Err(error) => {
                debug_assert!(false, "unable to get backup randomness from OS: {}", error);
            }
        }

        // perform 25 milliseconds of entropy gathering. ensure that at least 512 iterations occur.
        // This should generate anywhere between 100 and 10_000 bytes of real entropy, giving us a
        // substantial safety margin.
        let start = SystemTime::now();
        let mut iters = 0;
        while start.elapsed().expect(CLOCK_ERR).as_millis() < 25 || iters < 512 {
            iters += 1;

            // mix in the current time
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect(CLOCK_ERR)
                .as_nanos()
                .to_le_bytes();
            for i in 0..16 {
                base[i] ^= time[i];
            }
            base = hash(&base);
        }

        // No userspace entropy needs to be added to the backup at init as making the entropy_pool
        // secure is sufficient all by itself. The entropy pool is supposed to be secure, and the
        // backup pool is supposed to reset / rescue the entropy pool if the entropy pool gets
        // compromised. At this stage if the entropy pool is compromised then we can assume the
        // backup pool will also be compromised.
        let mut es = ENTROPY_STATE.lock().unwrap();
        es.entropy_pool.copy_from_slice(&base);
        es.backup_pool.copy_from_slice(&backup);
        drop(es);
    });
}

/// random256 provides 256 bits of entropy that has been hardened in userspace such that the
/// randomness that is likely to be secure even if the underlying operating system is not properly
/// generating secure entropy.
///
/// This call actively hardens the entropy pool when it is called. As a result it runs more slowly
/// and requires three full cryptographic hash operations each time it is invoked. It also requires
/// reading the system time 3 times. This ongoing entropy collection mechanism protects the caller
/// against active adversaries that may be using side channels to compromise the entropy state.
pub fn random256() -> [u8; 32] {
    // Throughout this function we use explict values as the number of bytes instead of calling
    // helpers like .len(). we found that being explicit made the mixing strategies easier to
    // reason about.

    init();

    // Grab the latest values in the entropy state. To maximize performance the mutex is only held
    // while the values are being read which means that multiple threads may read the same values
    // from the entropy pool. To protect against race conditions we have a usage counter which
    // increments on every access. Concurrent threads that read the same state will read different
    // values for the usage counter and therefore can generate independent entropy.
    let mut es_lock = ENTROPY_STATE.lock().unwrap();
    let mut entropy_pool = es_lock.entropy_pool;
    let mut backup_pool = es_lock.backup_pool;
    let usage_counter = es_lock.usage_counter;
    es_lock.usage_counter += 1;
    drop(es_lock);
    let usage_bytes: [u8; 16] = usage_counter.to_le_bytes();

    // After blocking for the mutex, grab the current system time. If an attacker is the caller the
    // attacker may be able to predict the exact value therefore this entropy is not independently
    // sufficient to harden our entropy pool. If the caller is not an attacker, it does provide
    // material entropy and will improve the quality of our entropy pools with negligiable
    // computational cost
    let start: [u8; 16] = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect(CLOCK_ERR)
        .as_nanos()
        .to_le_bytes();

    // xor the start time into the entropy pools. We use xor to ensure that any entropy which
    // already exists in the pools is preserved.
    for i in 0..15 {
        entropy_pool[i] ^= start[i];
        backup_pool[i] ^= start[i];
    }

    // xor the usage bytes into the entropy pools. This is not to introduce entropy but rather to
    // ensure that multiple threads that ended up using the same entropy pool value still get
    // different random outcomes.
    //
    // It is very import to ensure that the usage counter is the only element that gets mixed into
    // the final 16 bytes of the pools. If you mix in additional entropy, the entropy has a small
    // chance of perfectly cancelling out the usage counter which would allow multiple threads to
    // produce the exact same entropy when called.
    for i in 16..31 {
        entropy_pool[i] ^= usage_bytes[i - 16];
        backup_pool[i] ^= usage_bytes[i - 16];
    }

    // We now produce the output for the caller. The output is using the entropy that was produced
    // on the previous call to random256(). We produce the output before performing the hashing to
    // ensure that the current entropy state does not ever reveal anything about prior outputs.
    let output = hash(&entropy_pool);

    // The number of nanosecdons that are required to complete the sha256 hashing operations is a
    // variable number with an estimated 3-7 bits of true entropy. This entropy comes from the fact
    // that a CPU's execution speed depends on things like its temperature and current voltage.
    // despite what common sense may tell you, these things are highly variable even on the scale
    // of microseconds.
    //
    // Because of this variance, the current system time will contain a meaningful amount of
    // entropy. We will mix this entropy into the backup pool using xor.
    let output_timing_entropy = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect(CLOCK_ERR)
        .as_nanos()
        .to_le_bytes();
    for i in 0..15 {
        backup_pool[i] ^= output_timing_entropy[i];
    }

    // Hash the backup pool now that new information has been xor'd in. By hashing the backup pool
    // we guarantee that all of the new informmation gets spread evenly through the result.
    let new_backup = hash(&backup_pool);

    // We need to make sure that the entropy which gets added to the backup pool is different from
    // the entropy that gets added to the the entropy pool. The act of hashing the backup pool has
    // added new entropy to the system time which means we can use the current system time again to
    // create independent entropy for the entropy pool.
    let backup_timing_entropy = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect(CLOCK_ERR)
        .as_nanos()
        .to_le_bytes();
    for i in 0..15 {
        entropy_pool[i] ^= backup_timing_entropy[i];
    }

    // Hash the updated entropy pool so that the new entropy gets fully mixed into the pool. This
    // hashing operation has the added benefit of adding even more entropy to the system time which
    // is important to prevent the caller from knowing the exact timestamp that was created while
    // hashing the backup pool.
    let new_entropy = hash(&entropy_pool);

    // Add all of our new results back into the entropy pool.
    let mut es_lock = ENTROPY_STATE.lock().unwrap();
    for i in 0..32 {
        es_lock.entropy_pool[i] ^= new_entropy[i];
        es_lock.backup_pool[i] ^= new_backup[i];

        // If the backup pool has gathered enough entropy, mix the backup pool into the entropy
        // pool. Because usage counter is incremented every time the entropy pool is read, we
        // are guaranteed to mix in backup entropy once every 512 calls.
        //
        // The value of the backup pool is to reset a compromised entropy pool and restore it
        // to full randomness.
        if usage_counter % BACKUP_FREQUENCY == 0 {
            es_lock.entropy_pool[i] ^= es_lock.backup_pool[i];
        }
    }
    drop(es_lock);

    // Return the output that was generated previously. The entropy pool has already been updated
    // since generating the output which protects the current output even if the entropy pool is
    // compromised in the future.
    output
}

/// range64 returns an unbiased secure random u64 within [start, end).
pub fn range64(start: u64, end: u64) -> Result<u64, Error> {
    // Check that the range is valid.
    if start >= end {
        bail!("start must be strictly smaller than end");
    }
    let range = (end - start) as u128;

    // Establish the 'limit', above which the rng toss is considered invalid as it will bias the
    // result. If we get an rng toss that is above the limit, we will have to redo the rng toss.
    // The max range is u64::MAX but the rng space is u128::MAX, so the chances of getting a result
    // above the limit are 1/2^64 per toss in the worst case. It is cryptographically unlikely that
    // the user needs more than two tosses.
    let result: u64;
    let umax = u128::MAX;
    let limit = umax - (umax % range);
    loop {
        let mut base = [0u8; 16];
        let rng = random256();
        base.copy_from_slice(&rng[..16]);
        let rand = u128::from_le_bytes(base);
        if rand > limit {
            continue;
        }
        result = (rand % range) as u64;
        break;
    }
    Ok(result + start)
}

/// Implement a csprng for userspace-random so that it can be used for activities like generating
/// keypairs.
pub struct Csprng {
    // No state is required, just use the public functions.
}

impl rand_core::CryptoRng for Csprng {}

impl rand_core::RngCore for Csprng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(random256()[..4].try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(random256()[..8].try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let dlen = dest.len();
        let mut i = 0;
        while i + 32 < dlen {
            let rand = random256();
            dest[i..i + 32].copy_from_slice(&rand);
            i += 32;
        }
        if dlen % 32 == 0 {
            return;
        }

        let rand = random256();
        let need = dlen - i;
        dest[i..dlen].copy_from_slice(&rand[..need]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand_core::RngCore;

    #[test]
    // Perform a statistical test to look for basic mistakes in random256. Note that this test
    // passing is not an assurance that the data is truly random as lots of obviously non-random
    // data will pass this test.
    fn check_random256() {
        let tries = 100_000;

        // Count the number of times each byte value appears when generating random data.
        let mut frequencies = std::collections::HashMap::new();
        for _ in 0..tries {
            let rand = random256();
            for i in 0..rand.len() - 1 {
                match frequencies.get(&rand[i]) {
                    Some(num) => frequencies.insert(rand[i], num + 1),
                    None => frequencies.insert(rand[i], 1),
                };
            }
        }

        // Review the number of appearances of each byte value and look for statistical anomalies.
        for i in 0..255 {
            let num = frequencies.get(&i).unwrap();
            assert!(num > &(tries * 32 * 80 / 255 / 100));
            assert!(num < &(tries * 32 * 112 / 255 / 100));
        }
    }

    #[test]
    fn check_range64() {
        let tries = 10_000;
        for _ in 0..tries {
            let i = range64(0, 1).unwrap();
            assert!(i == 0);
            let i = range64(1, 2).unwrap();
            assert!(i == 1);
            range64(1, 1).unwrap_err();
            range64(1, 0).unwrap_err();
        }

        // Get a range of 256 and count the frequencies of each result, looking for statistical
        // anomalies. This isn't a robust statistcal test, it is just designed to catch obvious
        // errors such as off-by-one.
        let tries = 200_000;
        let mut frequencies = std::collections::HashMap::new();
        for _ in 0..tries {
            let rand = range64(1, 256).unwrap();
            match frequencies.get(&rand) {
                Some(num) => frequencies.insert(rand, num + 1),
                None => frequencies.insert(rand, 1),
            };
        }
        for i in 1..256 {
            let num = frequencies.get(&i).unwrap();
            if *num < tries / 255 * 80 / 100 {
                panic!(
                    "value {} appeared fewer times than expected: {} :: {}",
                    i,
                    num,
                    tries / 255 * 80 / 100
                );
            }
            if *num > tries / 255 * 125 / 100 {
                panic!(
                    "value {} appeared greater times than expected: {} :: {}",
                    i,
                    num,
                    tries / 255 * 125 / 100
                );
            }
        }
    }

    #[test]
    fn check_prng_impl() {
        // Basic test: see that we can use our csprng to create an ed25519 key.
        let mut csprng = Csprng {};
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        let msg = b"example message";
        let sig = keypair.sign(msg);
        keypair.public.verify_strict(msg, &sig).unwrap();

        // Use all of the methods of the cspring.
        let mut counter = std::collections::HashMap::new();
        for _ in 0..10_000 {
            let t = csprng.next_u32() as u64;
            match counter.get(&t) {
                None => counter.insert(t, 1),
                Some(v) => counter.insert(t, v + 1),
            };
        }
        for _ in 0..10_000 {
            let t = csprng.next_u64();
            match counter.get(&t) {
                None => counter.insert(t, 1),
                Some(v) => counter.insert(t, v + 1),
            };
        }

        for _ in 0..100 {
            let mut bytes = [0u8; 8008];
            csprng.fill_bytes(&mut bytes);
            for i in 0..1001 {
                let t = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
                match counter.get(&t) {
                    None => counter.insert(t, 1),
                    Some(v) => counter.insert(t, v + 1),
                };
            }
            let mut bytes = [0u8; 8008];
            csprng.try_fill_bytes(&mut bytes).unwrap();
            for i in 0..1001 {
                let t = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
                match counter.get(&t) {
                    None => counter.insert(t, 1),
                    Some(v) => counter.insert(t, v + 1),
                };
            }
        }

        for (key, value) in counter {
            if value > 10 {
                panic!("distribution does not appear to be even: {}:{}", key, value);
            }
        }
    }
}
