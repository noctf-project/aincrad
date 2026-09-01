use k8s_common::PortRange;

pub(crate) struct PortFinderIter {
    n: u64,
    state: u64,
    a: u64,
    c: u64,
    count: u64,
    start: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct PortFinderFactory {
    p: u64,
    n: u64,
    start: u16,
}

impl PortFinderFactory {
    /// Creates a PortFinder that yields every value in `0..n`
    /// exactly once, in a pseudo-random order.
    pub(crate) fn new(range: &PortRange) -> Self {
        let start = *range.0.start();
        let end = *range.0.end();
        let n = if end >= start {
            (end - start + 1) as u64
        } else {
            0
        };
        if n <= 1 {
            return Self { p: 0, n, start };
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

        Self { p, n, start }
    }

    pub(crate) fn random_cycle(&self) -> PortFinderIter {
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

        let seed: u64 = rand::random();

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
    fn test_full_permutation_coverage() {
        let range = PortRange(30000..=35000);
        let factory = PortFinderFactory::new(&range);

        let seq: Vec<u16> = factory.random_cycle().collect();
        assert_eq!(seq.len(), 5001);

        // Verify full permutation coverage (every port in range yielded exactly once)
        let mut sorted_seq = seq.clone();
        sorted_seq.sort();
        let expected: Vec<u16> = (30000..=35000).collect();
        assert_eq!(
            sorted_seq, expected,
            "Must yield every port in the range exactly once"
        );
    }

    #[test]
    fn test_different_cycles_produce_different_sequences() {
        let range = PortRange(30000..=35000);
        let factory = PortFinderFactory::new(&range);

        let seq1: Vec<u16> = factory.random_cycle().collect();
        let seq2: Vec<u16> = factory.random_cycle().collect();

        assert_ne!(
            seq1, seq2,
            "Independent cycles should produce different random permutations"
        );
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_edge_case_n_equals_0() {
        let range = PortRange(50000..=49999);
        let factory = PortFinderFactory::new(&range);
        let mut iter = factory.random_cycle();
        assert_eq!(iter.next(), None, "n=0 range must return None immediately");
    }

    #[test]
    fn test_edge_case_n_equals_1() {
        let range = PortRange(30000..=30000);
        let factory = PortFinderFactory::new(&range);

        for _ in 0..3 {
            let mut iter = factory.random_cycle();
            assert_eq!(iter.next(), Some(30000), "n=1 must yield the single port");
            assert_eq!(iter.next(), None, "n=1 must return None on second call");
        }
    }

    #[test]
    fn test_edge_case_n_equals_2() {
        let range = PortRange(20000..=20001);
        let factory = PortFinderFactory::new(&range);

        let seq: Vec<u16> = factory.random_cycle().collect();
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

            let seq: Vec<u16> = factory.random_cycle().collect();
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

            let seq: Vec<u16> = factory.random_cycle().collect();
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

            let seq: Vec<u16> = factory.random_cycle().collect();
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
