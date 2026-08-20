use std::time::Duration;

use async_compression::tokio::write::GzipEncoder;
use capnp_futures::serialize_packed;
use fluct::{Error, proto_capnp};
use tokio::{
    fs::File,
    io::{AsyncWrite, AsyncWriteExt, BufWriter},
    time::Instant,
};

use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

pub struct FileLogger {
    writer: Compat<Box<dyn AsyncWrite + Send + Unpin + 'static>>,
    instant: Instant,
    last_write: Duration,
}

impl FileLogger {
    pub fn new(file: File) -> Self {
        let compress = GzipEncoder::new(file);
        let writer = BufWriter::new(compress);
        Self {
            writer: TokioAsyncWriteCompatExt::compat_write(Box::new(writer)),
            last_write: Duration::ZERO,
            instant: Instant::now(),
        }
    }

    pub async fn write(&mut self, stream: u8, payload: &[u8]) -> Result<(), Error> {
        let mut message = ::capnp::message::Builder::new_default();
        let elapsed = self.instant.elapsed();
        {
            let mut res = message.init_root::<proto_capnp::data_frame::Builder>();
            res.set_stream(stream);
            res.set_time((elapsed - self.last_write).as_millis() as u32);
            res.set_payload(payload);
        }
        self.last_write = elapsed;

        serialize_packed::write_message(&mut self.writer, message).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.get_mut().flush().await
    }
}
