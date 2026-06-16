use crate::{CoreResult, FrameSink, FrameStream, InboundFrame};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use wa_crypto::NoiseHandshake;

pub type SharedNoiseHandshake = Arc<Mutex<NoiseHandshake>>;

#[must_use]
pub fn shared_noise_handshake(handshake: NoiseHandshake) -> SharedNoiseHandshake {
    Arc::new(Mutex::new(handshake))
}

pub struct NoiseFrameSink<S> {
    inner: S,
    noise: SharedNoiseHandshake,
}

impl<S> NoiseFrameSink<S> {
    #[must_use]
    pub fn new(inner: S, noise: SharedNoiseHandshake) -> Self {
        Self { inner, noise }
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

#[async_trait]
impl<S> FrameSink for NoiseFrameSink<S>
where
    S: FrameSink,
{
    async fn send(&mut self, frame: Bytes) -> CoreResult<()> {
        let encoded = {
            let mut noise = self.noise.lock().await;
            noise.encode_frame(&frame)?
        };
        self.inner.send(encoded).await
    }

    async fn close(&mut self) -> CoreResult<()> {
        self.inner.close().await
    }
}

pub struct NoiseFrameStream<R> {
    inner: R,
    noise: SharedNoiseHandshake,
    pending: VecDeque<Bytes>,
}

impl<R> NoiseFrameStream<R> {
    #[must_use]
    pub fn new(inner: R, noise: SharedNoiseHandshake) -> Self {
        Self {
            inner,
            noise,
            pending: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

#[async_trait]
impl<R> FrameStream for NoiseFrameStream<R>
where
    R: FrameStream,
{
    async fn recv(&mut self) -> CoreResult<Option<InboundFrame>> {
        if let Some(frame) = self.pending.pop_front() {
            return Ok(Some(InboundFrame::new(frame)));
        }

        loop {
            let Some(chunk) = self.inner.recv().await? else {
                return Ok(None);
            };
            let frames = {
                let mut noise = self.noise.lock().await;
                noise.push_frame_bytes(&chunk.payload)?
            };
            self.pending.extend(frames);

            if let Some(frame) = self.pending.pop_front() {
                return Ok(Some(InboundFrame::new(frame)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;
    use wa_crypto::{DEFAULT_NOISE_HEADER, generate_key_pair};

    struct MockSink {
        tx: mpsc::Sender<Bytes>,
        close_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl FrameSink for MockSink {
        async fn send(&mut self, frame: Bytes) -> CoreResult<()> {
            self.tx
                .send(frame)
                .await
                .map_err(|err| CoreError::Task(err.to_string()))
        }

        async fn close(&mut self) -> CoreResult<()> {
            self.close_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct MockStream {
        rx: mpsc::Receiver<InboundFrame>,
    }

    #[async_trait]
    impl FrameStream for MockStream {
        async fn recv(&mut self) -> CoreResult<Option<InboundFrame>> {
            Ok(self.rx.recv().await)
        }
    }

    #[tokio::test]
    async fn sink_encodes_noise_frame_before_send() {
        let (tx, mut rx) = mpsc::channel(1);
        let close_count = Arc::new(AtomicUsize::new(0));
        let noise = shared_noise_handshake(NoiseHandshake::new(generate_key_pair()));
        let mut sink = NoiseFrameSink::new(
            MockSink {
                tx,
                close_count: Arc::clone(&close_count),
            },
            noise,
        );

        sink.send(Bytes::from_static(b"hello")).await.unwrap();
        let encoded = rx.recv().await.unwrap();

        assert!(encoded.starts_with(&DEFAULT_NOISE_HEADER));
        assert_eq!(
            &encoded[DEFAULT_NOISE_HEADER.len()..],
            &[0, 0, 5, b'h', b'e', b'l', b'l', b'o']
        );

        sink.close().await.unwrap();
        assert_eq!(close_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn stream_decodes_noise_frame_chunks() {
        let (tx, rx) = mpsc::channel(2);
        let noise = shared_noise_handshake(NoiseHandshake::new(generate_key_pair()));
        let mut stream = NoiseFrameStream::new(MockStream { rx }, noise);

        tx.send(InboundFrame::new(Bytes::from_static(&[0, 0])))
            .await
            .unwrap();
        tx.send(InboundFrame::new(Bytes::from_static(&[
            5, b'h', b'e', b'l', b'l', b'o',
        ])))
        .await
        .unwrap();

        assert_eq!(
            stream.recv().await.unwrap().unwrap().payload,
            Bytes::from_static(b"hello")
        );
    }

    #[tokio::test]
    async fn stream_returns_none_when_inner_stream_ends() {
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let noise = shared_noise_handshake(NoiseHandshake::new(generate_key_pair()));
        let mut stream = NoiseFrameStream::new(MockStream { rx }, noise);

        assert!(stream.recv().await.unwrap().is_none());
    }
}
