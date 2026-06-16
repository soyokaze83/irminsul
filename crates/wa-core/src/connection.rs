use crate::{
    ConnectionState, CoreError, CoreResult, Event, EventHub, InboundBinaryNode, QueryManager,
    decode_inbound_binary_node, dispatch_binary_node,
};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wa_binary::{BinaryNode, encode_binary_node};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundFrame {
    pub tag: Option<String>,
    pub payload: Bytes,
}

impl InboundFrame {
    #[must_use]
    pub fn new(payload: Bytes) -> Self {
        Self { tag: None, payload }
    }

    #[must_use]
    pub fn tagged(tag: impl Into<String>, payload: Bytes) -> Self {
        Self {
            tag: Some(tag.into()),
            payload,
        }
    }
}

#[async_trait]
pub trait FrameSink: Send + 'static {
    async fn send(&mut self, frame: Bytes) -> CoreResult<()>;
    async fn close(&mut self) -> CoreResult<()>;
}

#[async_trait]
pub trait FrameStream: Send + 'static {
    async fn recv(&mut self) -> CoreResult<Option<InboundFrame>>;
}

#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

impl Connection {
    #[must_use]
    pub fn spawn<S, R>(
        sink: S,
        stream: R,
        queries: QueryManager,
        events: EventHub,
        outbound_capacity: usize,
    ) -> Self
    where
        S: FrameSink,
        R: FrameStream,
    {
        let (outbound_tx, outbound_rx) = mpsc::channel(outbound_capacity);
        let inner = Arc::new(ConnectionInner {
            outbound_tx,
            queries,
            events,
            closed: AtomicBool::new(false),
            outbound_task: Mutex::new(None),
            inbound_task: Mutex::new(None),
        });

        let outbound_inner = Arc::clone(&inner);
        let outbound_task =
            tokio::spawn(async move { run_outbound(sink, outbound_rx, outbound_inner).await });

        let inbound_inner = Arc::clone(&inner);
        let inbound_task = tokio::spawn(async move { run_inbound(stream, inbound_inner).await });

        store_task(&inner.outbound_task, outbound_task);
        store_task(&inner.inbound_task, inbound_task);
        inner
            .events
            .emit(Event::ConnectionUpdate(ConnectionState::Open));

        Self { inner }
    }

    #[must_use]
    pub fn queries(&self) -> &QueryManager {
        &self.inner.queries
    }

    #[must_use]
    pub fn events(&self) -> &EventHub {
        &self.inner.events
    }

    pub async fn send_frame(&self, frame: Bytes) -> CoreResult<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(CoreError::ConnectionClosed);
        }

        self.inner
            .outbound_tx
            .send(OutboundCommand::Send(frame))
            .await
            .map_err(|_| CoreError::ConnectionClosed)
    }

    pub async fn send_node(&self, node: &BinaryNode) -> CoreResult<()> {
        self.send_frame(encode_binary_node(node)?).await
    }

    pub async fn query(&self, tag: impl Into<String>, frame: Bytes) -> CoreResult<Bytes> {
        let waiter = self.inner.queries.register(tag.into())?;
        self.send_frame(frame).await?;
        waiter.wait().await
    }

    pub async fn query_node(&self, mut node: BinaryNode) -> CoreResult<InboundBinaryNode> {
        let tag = node
            .attrs
            .get("id")
            .cloned()
            .unwrap_or_else(|| self.inner.queries.next_tag());
        node.attrs.insert("id".to_owned(), tag.clone());

        let waiter = self.inner.queries.register(tag)?;
        self.send_node(&node).await?;
        let response = waiter.wait().await?;
        decode_inbound_binary_node(&response)
    }

    pub async fn close(&self) -> CoreResult<()> {
        let was_closed = self.inner.closed.swap(true, Ordering::AcqRel);

        let _ = self.inner.queries.close_pending()?;
        let _ = self.inner.outbound_tx.send(OutboundCommand::Close).await;

        if let Some(handle) = take_task(&self.inner.outbound_task) {
            join_task(handle).await?;
        }

        if let Some(handle) = take_task(&self.inner.inbound_task) {
            handle.abort();
            let _ = handle.await;
        }

        if !was_closed {
            self.inner
                .events
                .emit(Event::ConnectionUpdate(ConnectionState::Closed));
        }
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            mark_closed(&self.inner);
            abort_task(&self.inner.outbound_task);
            abort_task(&self.inner.inbound_task);
        }
    }
}

struct ConnectionInner {
    outbound_tx: mpsc::Sender<OutboundCommand>,
    queries: QueryManager,
    events: EventHub,
    closed: AtomicBool,
    outbound_task: Mutex<Option<JoinHandle<CoreResult<()>>>>,
    inbound_task: Mutex<Option<JoinHandle<CoreResult<()>>>>,
}

enum OutboundCommand {
    Send(Bytes),
    Close,
}

async fn run_outbound<S>(
    mut sink: S,
    mut outbound_rx: mpsc::Receiver<OutboundCommand>,
    inner: Arc<ConnectionInner>,
) -> CoreResult<()>
where
    S: FrameSink,
{
    while let Some(command) = outbound_rx.recv().await {
        match command {
            OutboundCommand::Send(frame) => {
                if let Err(err) = sink.send(frame).await {
                    mark_closed(&inner);
                    return Err(err);
                }
            }
            OutboundCommand::Close => {
                let result = sink.close().await;
                mark_closed(&inner);
                return result;
            }
        }
    }

    let result = sink.close().await;
    mark_closed(&inner);
    result
}

async fn run_inbound<R>(mut stream: R, inner: Arc<ConnectionInner>) -> CoreResult<()>
where
    R: FrameStream,
{
    loop {
        match stream.recv().await {
            Ok(Some(frame)) => {
                if let Some(tag) = frame.tag.as_deref()
                    && inner.queries.resolve(tag, frame.payload.clone())?
                {
                    continue;
                }

                if let Ok(inbound) = decode_inbound_binary_node(&frame.payload) {
                    dispatch_binary_node(&inner.queries, &inner.events, inbound)?;
                    continue;
                }

                inner.events.emit(Event::Frame(frame.payload));
            }
            Ok(None) => {
                mark_closed(&inner);
                return Ok(());
            }
            Err(err) => {
                mark_closed(&inner);
                return Err(err);
            }
        }
    }
}

fn mark_closed(inner: &ConnectionInner) {
    if !inner.closed.swap(true, Ordering::AcqRel) {
        let _ = inner.queries.close_pending();
        inner
            .events
            .emit(Event::ConnectionUpdate(ConnectionState::Closed));
    }
}

fn store_task(
    slot: &Mutex<Option<JoinHandle<CoreResult<()>>>>,
    handle: JoinHandle<CoreResult<()>>,
) {
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(handle);
    }
}

fn take_task(
    slot: &Mutex<Option<JoinHandle<CoreResult<()>>>>,
) -> Option<JoinHandle<CoreResult<()>>> {
    slot.lock().ok()?.take()
}

fn abort_task(slot: &Mutex<Option<JoinHandle<CoreResult<()>>>>) {
    if let Some(handle) = take_task(slot) {
        handle.abort();
    }
}

async fn join_task(handle: JoinHandle<CoreResult<()>>) -> CoreResult<()> {
    handle
        .await
        .map_err(|err| CoreError::Task(err.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::mpsc;
    use wa_binary::decode_binary_node;

    #[derive(Clone)]
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

    fn spawn_mock() -> (
        Connection,
        EventHub,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<InboundFrame>,
    ) {
        let events = EventHub::new(16);
        let queries = QueryManager::new(Some(std::time::Duration::from_secs(5)));
        let (sink_tx, sink_rx) = mpsc::channel(4);
        let (stream_tx, stream_rx) = mpsc::channel(4);
        let close_count = Arc::new(AtomicUsize::new(0));
        let connection = Connection::spawn(
            MockSink {
                tx: sink_tx,
                close_count,
            },
            MockStream { rx: stream_rx },
            queries,
            events.clone(),
            4,
        );

        (connection, events, sink_rx, stream_tx)
    }

    #[tokio::test]
    async fn spawn_emits_open_event() {
        let events = EventHub::new(16);
        let mut events_rx = events.subscribe();
        let queries = QueryManager::new(None);
        let (sink_tx, _sink_rx) = mpsc::channel(4);
        let (_stream_tx, stream_rx) = mpsc::channel(4);

        let _connection = Connection::spawn(
            MockSink {
                tx: sink_tx,
                close_count: Arc::new(AtomicUsize::new(0)),
            },
            MockStream { rx: stream_rx },
            queries,
            events,
            4,
        );

        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Open)
        ));
    }

    #[tokio::test]
    async fn sends_frames_through_bounded_queue() {
        let (connection, _events, mut sink_rx, _stream_tx) = spawn_mock();

        connection
            .send_frame(Bytes::from_static(b"out"))
            .await
            .unwrap();

        assert_eq!(sink_rx.recv().await.unwrap(), Bytes::from_static(b"out"));
    }

    #[tokio::test]
    async fn resolves_tagged_inbound_frame_to_query_waiter() {
        let (connection, _events, mut sink_rx, stream_tx) = spawn_mock();
        let query_task = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .query("abc", Bytes::from_static(b"request"))
                    .await
            })
        };

        assert_eq!(
            sink_rx.recv().await.unwrap(),
            Bytes::from_static(b"request")
        );
        stream_tx
            .send(InboundFrame::tagged("abc", Bytes::from_static(b"response")))
            .await
            .unwrap();

        assert_eq!(
            query_task.await.unwrap().unwrap(),
            Bytes::from_static(b"response")
        );
    }

    #[tokio::test]
    async fn sends_binary_nodes_as_encoded_frames() {
        let (connection, _events, mut sink_rx, _stream_tx) = spawn_mock();
        let node = BinaryNode::new("iq")
            .with_attr("id", "abc")
            .with_attr("type", "get");

        connection.send_node(&node).await.unwrap();

        let sent = sink_rx.recv().await.unwrap();
        assert_eq!(decode_binary_node(&sent).unwrap(), node);
    }

    #[tokio::test]
    async fn query_node_registers_tag_and_decodes_response() {
        let (connection, _events, mut sink_rx, stream_tx) = spawn_mock();
        let query_task = {
            let connection = connection.clone();
            tokio::spawn(async move { connection.query_node(BinaryNode::new("iq")).await })
        };

        let sent = decode_binary_node(&sink_rx.recv().await.unwrap()).unwrap();
        let tag = sent.attrs.get("id").unwrap().clone();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", tag)
                        .with_attr("type", "result"),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        let response = query_task.await.unwrap().unwrap();
        assert_eq!(response.node.attrs["type"], "result");
    }

    #[tokio::test]
    async fn emits_unmatched_inbound_frames() {
        let (_connection, events, _sink_rx, stream_tx) = spawn_mock();
        let mut events_rx = events.subscribe();

        stream_tx
            .send(InboundFrame::new(Bytes::from_static(b"event")))
            .await
            .unwrap();

        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::Frame(payload) if payload == Bytes::from_static(b"event")
        ));
    }

    #[tokio::test]
    async fn emits_unmatched_inbound_binary_nodes_as_raw_nodes() {
        let (_connection, events, _sink_rx, stream_tx) = spawn_mock();
        let mut events_rx = events.subscribe();
        let node = BinaryNode::new("message").with_attr("id", "event");

        stream_tx
            .send(InboundFrame::new(encode_binary_node(&node).unwrap()))
            .await
            .unwrap();

        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::RawNode(received) if received == node
        ));
    }

    #[tokio::test]
    async fn close_fails_pending_queries() {
        let (connection, _events, mut sink_rx, _stream_tx) = spawn_mock();
        let query_task = {
            let connection = connection.clone();
            tokio::spawn(async move {
                connection
                    .query("abc", Bytes::from_static(b"request"))
                    .await
            })
        };

        assert_eq!(
            sink_rx.recv().await.unwrap(),
            Bytes::from_static(b"request")
        );
        connection.close().await.unwrap();

        assert!(matches!(
            query_task.await.unwrap(),
            Err(CoreError::ConnectionClosed)
        ));
    }

    #[tokio::test]
    async fn inbound_end_marks_connection_closed() {
        let (connection, events, _sink_rx, stream_tx) = spawn_mock();
        let mut events_rx = events.subscribe();

        drop(stream_tx);

        assert!(matches!(
            events_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Closed)
        ));
        assert!(matches!(
            connection.send_frame(Bytes::from_static(b"late")).await,
            Err(CoreError::ConnectionClosed)
        ));
    }

    #[tokio::test]
    async fn close_after_inbound_end_closes_sink_task() {
        let events = EventHub::new(16);
        let queries = QueryManager::new(None);
        let (sink_tx, _sink_rx) = mpsc::channel(4);
        let (stream_tx, stream_rx) = mpsc::channel(4);
        let close_count = Arc::new(AtomicUsize::new(0));
        let connection = Connection::spawn(
            MockSink {
                tx: sink_tx,
                close_count: Arc::clone(&close_count),
            },
            MockStream { rx: stream_rx },
            queries,
            events,
            4,
        );

        drop(stream_tx);
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        connection.close().await.unwrap();

        assert_eq!(close_count.load(Ordering::Acquire), 1);
    }
}
