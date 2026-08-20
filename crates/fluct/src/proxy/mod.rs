mod challenge;
mod flag;
mod handler;

use std::time::Duration;

use fluct::Error;
pub use handler::Handler;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    select,
    time::{Instant, sleep},
};

async fn get_line<R>(reader: &mut R, max: usize, input_time: Duration) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let instant = Instant::now();
    let mut r = 0;
    let mut valid = false;
    let mut uid = vec![0u8; max + 1]; // To account for \r\n
    while r < max {
        let elapsed = instant.elapsed();
        if elapsed >= input_time {
            break;
        }
        select! {
            Ok(b) = reader.read_u8() => {
                if b == b'\n' {
                    valid = true;
                    break;
                } else {
                    uid[r] = b;
                    r += 1;
                }
            },
            _ = sleep(input_time - elapsed) => {
                break;
            }
        }
    }
    if valid {
        if r == 0 {
            return Ok(b"".to_vec());
        } else if uid[r - 1] == b'\r' {
            uid.truncate(r - 1);
        } else {
            uid.truncate(r);
        }
        return Ok(uid);
    }

    Err("invalid string input".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_get_line_normal_and_crlf() {
        let mut input1 = Cursor::new(b"hello world\n");
        let res1 = get_line(&mut input1, 64, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(res1, b"hello world");

        let mut input2 = Cursor::new(b"hello crlf\r\n");
        let res2 = get_line(&mut input2, 64, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(res2, b"hello crlf");

        let mut input_empty = Cursor::new(b"\n");
        let res_empty = get_line(&mut input_empty, 64, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(res_empty, b"");
    }

    #[tokio::test]
    async fn test_get_line_exceeds_max() {
        let mut input = Cursor::new(b"1234567890\n");
        let res = get_line(&mut input, 5, Duration::from_secs(1)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_line_timeout() {
        let (mut _client, mut server) = tokio::io::duplex(64);
        let handle =
            tokio::spawn(async move { get_line(&mut server, 64, Duration::from_millis(50)).await });
        let res = handle.await.unwrap();
        assert!(res.is_err());
    }
}
