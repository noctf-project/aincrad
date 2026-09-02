use std::{
    future::Future,
    io,
    os::fd::RawFd,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use fluct::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    select,
    time::{Instant, Sleep, sleep},
};

/// Enables TCP keepalive on a socket file descriptor (60s idle, 10s interval, 3 probes).
pub fn set_tcp_keepalive(fd: RawFd) -> io::Result<()> {
    let opt: libc::c_int = 1;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    {
        let idle: libc::c_int = 60;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &idle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let intvl: libc::c_int = 10;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                &intvl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let cnt: libc::c_int = 3;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                &cnt as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    Ok(())
}

/// Reads a single line from an async reader with maximum length and timeout constraints.
pub async fn get_line<R>(reader: &mut R, max: usize, input_time: Duration) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let instant = Instant::now();
    let mut r = 0;
    let mut valid = false;
    let mut uid = vec![0u8; max + 1];
    while r < max {
        let elapsed = instant.elapsed();
        if elapsed >= input_time {
            break;
        }
        select! {
            res = reader.read_u8() => {
                match res {
                    Ok(b) => {
                        if b == b'\n' {
                            valid = true;
                            break;
                        } else {
                            uid[r] = b;
                            r += 1;
                        }
                    }
                    Err(e) => return Err(Box::new(e)),
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
        }
        if uid[r - 1] == b'\r' {
            r -= 1;
        }
        uid.truncate(r);
        Ok(uid)
    } else {
        Err("get line error".into())
    }
}

/// An AsyncRead adapter that resets an idle timer whenever bytes are read.
pub struct IdleTimeoutReader<R> {
    inner: R,
    timeout: Duration,
    sleep: Pin<Box<Sleep>>,
}

impl<R: AsyncRead + Unpin> IdleTimeoutReader<R> {
    pub fn new(inner: R, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for IdleTimeoutReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let prev_len = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes_read = buf.filled().len() - prev_len;
                if bytes_read > 0 {
                    let deadline = Instant::now() + self.timeout;
                    self.sleep.as_mut().reset(deadline);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                if Future::poll(Pin::new(&mut self.sleep), cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

/// Copies data bidirectionally between client and backend streams.
///
/// Handles TCP half-close asymmetry:
/// - If the backend closes (`b_rx` reaches EOF), the challenge has terminated and the proxy shuts down immediately.
/// - If the client closes (`c_rx` reaches EOF), the proxy keeps running until the backend finishes outputting.
pub async fn copy_bidirectional<R1, W1, R2, W2>(
    mut c_rx: R1,
    mut b_tx: W1,
    mut b_rx: R2,
    mut c_tx: W2,
) -> Result<(), Error>
where
    R1: AsyncRead + Unpin,
    W1: AsyncWrite + Unpin,
    R2: AsyncRead + Unpin,
    W2: AsyncWrite + Unpin,
{
    let client_to_server = async {
        tokio::io::copy(&mut c_rx, &mut b_tx).await?;
        b_tx.shutdown().await
    };
    let server_to_client = async {
        tokio::io::copy(&mut b_rx, &mut c_tx).await?;
        c_tx.shutdown().await
    };

    tokio::pin!(client_to_server);
    tokio::pin!(server_to_client);

    select! {
        res = &mut server_to_client => {
            res?;
        }
        res = &mut client_to_server => {
            res?;
            server_to_client.await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_get_line_normal_and_crlf() {
        let mut input = Cursor::new(b"hello world\n");
        let line = get_line(&mut input, 64, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(line, b"hello world");

        let mut input_crlf = Cursor::new(b"crlf line\r\n");
        let line_crlf = get_line(&mut input_crlf, 64, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(line_crlf, b"crlf line");
    }

    #[tokio::test]
    async fn test_get_line_exceeds_max() {
        let mut input = Cursor::new(b"too long line here\n");
        let res = get_line(&mut input, 5, Duration::from_secs(1)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_line_timeout() {
        let (mut client_rx, _client_tx) = tokio::io::duplex(64);
        let res = get_line(&mut client_rx, 64, Duration::from_millis(50)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_get_line_eof_immediate_error() {
        let mut empty = Cursor::new(b"");
        let res = get_line(&mut empty, 64, Duration::from_secs(10)).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_idle_timeout_reader_resets_on_read() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut reader = IdleTimeoutReader::new(rx, Duration::from_millis(150));

        let writer_task = tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(80)).await;
                tx.write_all(b"ping").await.unwrap();
            }
        });

        let mut buf = [0u8; 4];
        for _ in 0..3 {
            reader.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        }

        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_idle_timeout_reader_expires_on_inactivity() {
        let (_tx, rx) = tokio::io::duplex(64);
        let mut reader = IdleTimeoutReader::new(rx, Duration::from_millis(50));

        let mut buf = [0u8; 4];
        let res = reader.read_exact(&mut buf).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn test_idle_timeout_reader_handles_immediate_eof() {
        let (tx, rx) = tokio::io::duplex(64);
        drop(tx);
        let mut reader = IdleTimeoutReader::new(rx, Duration::from_millis(200));

        let mut buf = [0u8; 4];
        let bytes_read = reader.read(&mut buf).await.unwrap();
        assert_eq!(bytes_read, 0);
    }

    #[tokio::test]
    async fn test_copy_bidirectional_data_transfer() {
        let (client_peer, proxy_client) = tokio::io::duplex(64);
        let (mut client_read, mut client_write) = tokio::io::split(client_peer);
        let (c_rx, c_tx) = tokio::io::split(proxy_client);

        let (backend_peer, proxy_backend) = tokio::io::duplex(64);
        let (mut backend_read, mut backend_write) = tokio::io::split(backend_peer);
        let (b_rx, b_tx) = tokio::io::split(proxy_backend);

        let proxy_task =
            tokio::spawn(async move { copy_bidirectional(c_rx, b_tx, b_rx, c_tx).await });

        client_write.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        backend_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        backend_write.write_all(b"pong").await.unwrap();
        let mut resp = [0u8; 4];
        client_read.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"pong");

        client_write.shutdown().await.unwrap();
        backend_write.shutdown().await.unwrap();
        assert!(proxy_task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_copy_bidirectional_server_closes_first() {
        let (client_peer, proxy_client) = tokio::io::duplex(64);
        let (mut client_read, _client_write) = tokio::io::split(client_peer);
        let (c_rx, c_tx) = tokio::io::split(proxy_client);

        let (backend_peer, proxy_backend) = tokio::io::duplex(64);
        let (_backend_read, mut backend_write) = tokio::io::split(backend_peer);
        let (b_rx, b_tx) = tokio::io::split(proxy_backend);

        let proxy_task =
            tokio::spawn(async move { copy_bidirectional(c_rx, b_tx, b_rx, c_tx).await });

        // Server writes goodbye and terminates
        backend_write.write_all(b"bye").await.unwrap();
        backend_write.shutdown().await.unwrap();

        // Client reads goodbye
        let mut resp = [0u8; 3];
        client_read.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"bye");

        // Client write stream was never closed, but proxy shuts down because server finished
        assert!(proxy_task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_copy_bidirectional_client_closes_first() {
        let (client_peer, proxy_client) = tokio::io::duplex(64);
        let (mut client_read, mut client_write) = tokio::io::split(client_peer);
        let (c_rx, c_tx) = tokio::io::split(proxy_client);

        let (backend_peer, proxy_backend) = tokio::io::duplex(64);
        let (mut backend_read, mut backend_write) = tokio::io::split(backend_peer);
        let (b_rx, b_tx) = tokio::io::split(proxy_backend);

        let proxy_task =
            tokio::spawn(async move { copy_bidirectional(c_rx, b_tx, b_rx, c_tx).await });

        // Client sends payload and closes its input half
        client_write.write_all(b"payload").await.unwrap();
        client_write.shutdown().await.unwrap();

        // Backend reads the payload
        let mut buf = [0u8; 7];
        backend_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"payload");

        // Backend writes response and closes
        tokio::time::sleep(Duration::from_millis(10)).await;
        backend_write.write_all(b"flag").await.unwrap();
        backend_write.shutdown().await.unwrap();

        // Client reads the flag
        let mut resp = [0u8; 4];
        client_read.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"flag");

        assert!(proxy_task.await.unwrap().is_ok());
    }
}
