use base64::Engine;
use base64::prelude::BASE64_URL_SAFE;
use crypto_ops::fixed_time_eq;
use fluct::Error;
use kctf_pow::ChallengeParams;
use rand::rngs::StdRng;
use std::cell::RefCell;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::crypto::hash::hmac_sha256;

use super::get_line;

const MAX_SIZE: usize = 2048;
const MAX_INPUT_TIME: Duration = Duration::from_secs(60);

#[derive(PartialEq, PartialOrd, Debug)]
pub enum ChallengeSolveState {
    Solved = 0,
    Bypassed = 1,
}

pub struct Challenge {}

impl Challenge {
    thread_local! {
        pub static RNG: RefCell<StdRng> = RefCell::new(rand::make_rng());
    }
    pub async fn solve<R, W>(
        difficulty: u64,
        bypass: &[u8],
        rx: &mut R,
        tx: &mut W,
    ) -> Option<ChallengeSolveState>
    where
        R: AsyncRead + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        Self::do_solve(difficulty, bypass, rx, tx)
            .await
            .unwrap_or_default()
    }

    async fn do_solve<R, W>(
        difficulty: u64,
        bypass: &[u8],
        rx: &mut R,
        tx: &mut W,
    ) -> Result<Option<ChallengeSolveState>, Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let chall = ChallengeParams::generate_challenge(difficulty as u32);
        tx.write_all(
            format!(
                "== proof of work: https://duc.tf/pow-solver ==\n{}\n",
                chall
            )
            .as_bytes(),
        )
        .await?;

        let duration = MAX_INPUT_TIME + Duration::from_micros(difficulty * 200);
        let line = get_line(rx, MAX_SIZE, duration).await?;
        let input = String::from_utf8(line.clone())?;

        let solution = hmac_sha256(bypass, chall.to_string().as_bytes());
        if let Ok(raw) = BASE64_URL_SAFE.decode(&line)
            && fixed_time_eq(&raw, &solution)
        {
            return Ok(Some(ChallengeSolveState::Bypassed));
        }

        let result = chall.check(&input);
        let result = result?;
        if result {
            Ok(Some(ChallengeSolveState::Solved))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::challenge::ChallengeSolveState;

    #[test]
    fn test_challenge_solve_state_ordering() {
        assert!(ChallengeSolveState::Bypassed > ChallengeSolveState::Solved);
    }
}
