use siphasher::sip::SipHasher24;

use crate::config::PortRange;

pub struct PortFinderIter {
    n: u64,
    state: u64,
    a: u64,
    c: u64,
    count: u64,
    start: u16,
}

#[derive(Clone, Debug)]
pub struct PortFinderFactory {
    hasher: SipHasher24,
    p: u64,
    n: u64,
    start: u16,
}

impl PortFinderFactory {
    /// Creates a PortFinder that yields every value in `0..n`
    /// exactly once, in a pseudo-random order.
    pub fn new(range: &PortRange) -> Self {
        let key1: u64 = rand::random();
        let key2: u64 = rand::random();
        let hasher = SipHasher24::new_with_keys(key1, key2);

        let start = *range.0.start();
        let end = *range.0.end();
        let n = if end >= start {
            (end - start + 1) as u64
        } else {
            0
        };
        if n <= 1 {
            return Self {
                hasher,
                p: 0,
                n,
                start,
            };
        }

        // Product of distinct prime factors of n.
        let mut temp = n;
        let mut p = 1;
        let mut d = 2;

        while d * d <= temp {
            if temp % d == 0 {
                p *= d;

                while temp % d == 0 {
                    temp /= d;
                }
            }

            d += 1;
        }

        if temp > 1 {
            p *= temp;
        }

        // Hull-Dobell condition: if 4 | n, then 4 | (a - 1).
        if n % 4 == 0 {
            p *= 2;
        }

        Self {
            hasher,
            p,
            n,
            start,
        }
    }

    pub fn cycle(&self, key: &str) -> PortFinderIter {
        if self.n <= 1 {
            return PortFinderIter {
                n: self.n,
                state: 0,
                a: 1,
                c: 0,
                count: 0,
                start: self.start,
            };
        }

        let seed = self.hasher.hash(key.as_bytes());

        // Use the highest 32 bits for k
        let k = ((seed >> 32) % 100) + 1;
        let a = 1 + self.p * k;
        let n = self.n;

        // Use the middle 16 bits for 'c'
        let mut c = (seed >> 16) % n;
        if c == 0 {
            c = 1;
        }

        while gcd(c, n) != 1 {
            c += 1;
            if c == n {
                c = 1;
            }
        }

        // Use the lowest 16 bits for the initial state
        PortFinderIter {
            n,
            state: seed % n,
            a,
            c,
            count: 0,
            start: self.start,
        }
    }
}

impl Iterator for PortFinderIter {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= self.n {
            return None;
        }

        let current = self.state;

        self.state = (self.a * self.state + self.c) % self.n;
        self.count += 1;

        Some(self.start + current as u16)
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_factory_same_string_same_sequence() {
        let range = PortRange(30000..=35000);
        let factory = PortFinderFactory::new(&range);

        let key = "test-route-key";
        let seq1: Vec<u16> = factory.cycle(key).collect();
        let seq2: Vec<u16> = factory.cycle(key).collect();

        assert_eq!(
            seq1, seq2,
            "Same factory and key must produce identical sequences"
        );
        assert_eq!(seq1.len(), 5001);

        // Verify full permutation coverage (every port in range yielded exactly once)
        let mut sorted_seq = seq1.clone();
        sorted_seq.sort();
        let expected: Vec<u16> = (30000..=35000).collect();
        assert_eq!(
            sorted_seq, expected,
            "Must yield every port in the range exactly once"
        );
    }

    #[test]
    fn test_different_factories_different_sequences() {
        let range = PortRange(30000..=35000);
        let keys = [
            "route-alpha",
            "route-beta",
            "route-gamma",
            "route-delta",
            "route-epsilon",
        ];

        let factory1 = PortFinderFactory::new(&range);
        let factory2 = PortFinderFactory::new(&range);

        // Compare sequences across keys to avoid rare 1-in-60,000 random seed collision
        let mut any_different = false;
        for key in keys {
            let seq1: Vec<u16> = factory1.cycle(key).collect();
            let seq2: Vec<u16> = factory2.cycle(key).collect();
            if seq1 != seq2 {
                any_different = true;
                break;
            }
        }

        assert!(
            any_different,
            "Different factory instances with independent RandomStates should produce different sequences"
        );
    }

    #[test]
    fn test_edge_case_n_equals_0() {
        let range = PortRange(50000..=49999);
        let factory = PortFinderFactory::new(&range);
        let mut iter = factory.cycle("any-key");
        assert_eq!(iter.next(), None, "n=0 range must return None immediately");
    }

    #[test]
    fn test_edge_case_n_equals_1() {
        let range = PortRange(30000..=30000);
        let factory = PortFinderFactory::new(&range);

        for key in ["key1", "key2", "key3"] {
            let mut iter = factory.cycle(key);
            assert_eq!(iter.next(), Some(30000), "n=1 must yield the single port");
            assert_eq!(iter.next(), None, "n=1 must return None on second call");
        }
    }

    #[test]
    fn test_edge_case_n_equals_2() {
        let range = PortRange(20000..=20001);
        let factory = PortFinderFactory::new(&range);

        let seq: Vec<u16> = factory.cycle("key-two").collect();
        assert_eq!(seq.len(), 2);
        assert!(seq.contains(&20000));
        assert!(seq.contains(&20001));
        assert_ne!(seq[0], seq[1], "n=2 must yield distinct ports");
    }

    #[test]
    fn test_edge_case_powers_of_two() {
        // Hull-Dobell 4 | (a - 1) condition applies when 4 | n
        let powers_of_two = [4, 8, 16, 64, 256, 1024, 4096];
        for size in powers_of_two {
            let start = 10000;
            let end = start + size - 1;
            let range = PortRange(start..=end);
            let factory = PortFinderFactory::new(&range);

            let seq: Vec<u16> = factory.cycle("pow2-key").collect();
            assert_eq!(
                seq.len(),
                size as usize,
                "Must yield exactly n elements for size {size}"
            );

            let mut sorted = seq.clone();
            sorted.sort();
            let expected: Vec<u16> = (start..=end).collect();
            assert_eq!(
                sorted, expected,
                "Power of two n={size} must yield full permutation without duplicates"
            );
        }
    }

    #[test]
    fn test_edge_case_prime_lengths() {
        let primes = [3, 7, 13, 97, 509, 1009];
        for prime in primes {
            let start = 20000;
            let end = start + prime - 1;
            let range = PortRange(start..=end);
            let factory = PortFinderFactory::new(&range);

            let seq: Vec<u16> = factory.cycle("prime-key").collect();
            assert_eq!(seq.len(), prime as usize);

            let mut sorted = seq.clone();
            sorted.sort();
            let expected: Vec<u16> = (start..=end).collect();
            assert_eq!(
                sorted, expected,
                "Prime length n={prime} must yield full permutation"
            );
        }
    }

    #[test]
    fn test_edge_case_composite_lengths() {
        let composites = [6, 12, 15, 30, 100, 360, 1000];
        for comp in composites {
            let start = 30000;
            let end = start + comp - 1;
            let range = PortRange(start..=end);
            let factory = PortFinderFactory::new(&range);

            let seq: Vec<u16> = factory.cycle("composite-key").collect();
            assert_eq!(seq.len(), comp as usize);

            let mut sorted = seq.clone();
            sorted.sort();
            let expected: Vec<u16> = (start..=end).collect();
            assert_eq!(
                sorted, expected,
                "Composite length n={comp} must yield full permutation"
            );
        }
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 18), 6);
        assert_eq!(gcd(17, 31), 1);
        assert_eq!(gcd(100, 25), 25);
        assert_eq!(gcd(1, 42), 1);
        assert_eq!(gcd(0, 5), 5);
    }
}
