use base64::Engine;
use base64::prelude::BASE64_URL_SAFE;
use crypto_ops::fixed_time_eq;
use fluct::Error;
use kctf_pow::ChallengeParams;
use rand::rngs::StdRng;
use std::cell::RefCell;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::hash::hmac_sha256;

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
    use super::*;
    use tokio::io::AsyncBufReadExt;

    #[test]
    fn test_challenge_solve_state_ordering() {
        assert!(ChallengeSolveState::Bypassed > ChallengeSolveState::Solved);
    }

    #[tokio::test]
    async fn test_challenge_admin_bypass_success() {
        let (mut client_rx, mut client_tx) = tokio::io::duplex(1024);
        let (server_rx, mut server_tx) = tokio::io::duplex(1024);

        let secret = b"supersecret";

        let solve_task = tokio::spawn(async move {
            let mut rx = server_rx;
            Challenge::solve(100, secret, &mut rx, &mut client_tx).await
        });

        let mut reader = tokio::io::BufReader::new(&mut client_rx);
        let mut banner = String::new();
        reader.read_line(&mut banner).await.unwrap();
        let mut chall_str = String::new();
        reader.read_line(&mut chall_str).await.unwrap();
        let chall_trimmed = chall_str.trim();

        let token = hmac_sha256(secret, chall_trimmed.as_bytes());
        let token_b64 = BASE64_URL_SAFE.encode(token);

        server_tx
            .write_all(format!("{token_b64}\n").as_bytes())
            .await
            .unwrap();

        let state = solve_task.await.unwrap();
        assert_eq!(state, Some(ChallengeSolveState::Bypassed));
    }

    #[tokio::test]
    async fn test_challenge_admin_bypass_wrong_token() {
        let (mut client_rx, mut client_tx) = tokio::io::duplex(1024);
        let (server_rx, mut server_tx) = tokio::io::duplex(1024);

        let secret = b"supersecret";

        let solve_task = tokio::spawn(async move {
            let mut rx = server_rx;
            Challenge::solve(100, secret, &mut rx, &mut client_tx).await
        });

        let mut reader = tokio::io::BufReader::new(&mut client_rx);
        let mut banner = String::new();
        reader.read_line(&mut banner).await.unwrap();
        let mut chall_str = String::new();
        reader.read_line(&mut chall_str).await.unwrap();

        server_tx.write_all(b"wrong_token\n").await.unwrap();

        let state = solve_task.await.unwrap();
        assert_eq!(state, None);
    }
}
