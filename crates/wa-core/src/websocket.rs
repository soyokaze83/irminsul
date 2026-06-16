use crate::{
    Connection, CoreError, CoreResult, EventHub, FrameSink, FrameStream, InboundFrame, QueryManager,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type ClientSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type ClientWrite = SplitSink<ClientSocket, Message>;
type ClientRead = SplitStream<ClientSocket>;

pub type WebSocketFrameSink = TungsteniteFrameSink<ClientWrite>;
pub type WebSocketFrameStream = TungsteniteFrameStream<ClientRead>;

pub async fn connect_websocket_transport(
    url: impl tokio_tungstenite::tungstenite::client::IntoClientRequest + Unpin,
) -> CoreResult<(WebSocketFrameSink, WebSocketFrameStream)> {
    let (socket, _response) = connect_async(url).await?;
    let (sink, stream) = socket.split();
    Ok((
        TungsteniteFrameSink::new(sink),
        TungsteniteFrameStream::new(stream),
    ))
}

pub async fn connect_websocket(
    url: impl tokio_tungstenite::tungstenite::client::IntoClientRequest + Unpin,
    queries: QueryManager,
    events: EventHub,
    outbound_capacity: usize,
) -> CoreResult<Connection> {
    let (sink, stream) = connect_websocket_transport(url).await?;
    Ok(Connection::spawn(
        sink,
        stream,
        queries,
        events,
        outbound_capacity,
    ))
}

pub struct TungsteniteFrameSink<S> {
    sink: S,
}

impl<S> TungsteniteFrameSink<S> {
    #[must_use]
    pub fn new(sink: S) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl<S> FrameSink for TungsteniteFrameSink<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send + Unpin + 'static,
{
    async fn send(&mut self, frame: Bytes) -> CoreResult<()> {
        self.sink.send(Message::Binary(frame)).await?;
        Ok(())
    }

    async fn close(&mut self) -> CoreResult<()> {
        self.sink.close().await?;
        Ok(())
    }
}

pub struct TungsteniteFrameStream<R> {
    stream: R,
}

impl<R> TungsteniteFrameStream<R> {
    #[must_use]
    pub fn new(stream: R) -> Self {
        Self { stream }
    }
}

#[async_trait]
impl<R> FrameStream for TungsteniteFrameStream<R>
where
    R: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Send
        + Unpin
        + 'static,
{
    async fn recv(&mut self) -> CoreResult<Option<InboundFrame>> {
        loop {
            let Some(message) = self.stream.next().await else {
                return Ok(None);
            };

            match message? {
                Message::Binary(bytes) => return Ok(Some(InboundFrame::new(bytes))),
                Message::Close(_frame) => return Ok(None),
                Message::Ping(_payload) | Message::Pong(_payload) => continue,
                Message::Frame(_raw) => continue,
                Message::Text(_text) => {
                    return Err(CoreError::Protocol(
                        "unexpected text websocket message".to_owned(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionState, Event};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::accept_async;

    #[tokio::test]
    async fn websocket_transport_sends_binary_frames() {
        let (url, server_ready) = spawn_server(async |socket| {
            let (mut sink, mut stream) = socket.split();
            let message = stream.next().await.unwrap().unwrap();
            assert_eq!(message, Message::Binary(Bytes::from_static(b"client")));
            sink.send(Message::Binary(Bytes::from_static(b"server")))
                .await
                .unwrap();
        })
        .await;

        let (mut sink, mut stream) = connect_websocket_transport(url).await.unwrap();
        server_ready.await.unwrap();
        sink.send(Bytes::from_static(b"client")).await.unwrap();

        let frame = stream.recv().await.unwrap().unwrap();
        assert_eq!(frame.payload, Bytes::from_static(b"server"));
    }

    #[tokio::test]
    async fn websocket_stream_rejects_text_messages() {
        let (url, server_ready) = spawn_server(async |socket| {
            let (mut sink, _stream) = socket.split();
            sink.send(Message::Text("not-binary".into())).await.unwrap();
        })
        .await;

        let (_sink, mut stream) = connect_websocket_transport(url).await.unwrap();
        server_ready.await.unwrap();

        assert!(matches!(
            stream.recv().await,
            Err(CoreError::Protocol(message)) if message.contains("text")
        ));
    }

    #[tokio::test]
    async fn websocket_connection_routes_binary_frames() {
        let (url, server_ready) = spawn_server(async |socket| {
            let (mut sink, mut stream) = socket.split();
            let message = stream.next().await.unwrap().unwrap();
            assert_eq!(message, Message::Binary(Bytes::from_static(b"request")));
            sink.send(Message::Binary(Bytes::from_static(b"event")))
                .await
                .unwrap();
        })
        .await;

        let events = EventHub::new(8);
        let mut event_rx = events.subscribe();
        let queries = QueryManager::new(None);
        let connection = connect_websocket(url, queries, events, 4).await.unwrap();
        server_ready.await.unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            Event::ConnectionUpdate(ConnectionState::Open)
        ));

        connection
            .send_frame(Bytes::from_static(b"request"))
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            Event::Frame(payload) if payload == Bytes::from_static(b"event")
        ));
        connection.close().await.unwrap();
    }

    async fn spawn_server<F, Fut>(handler: F) -> (String, oneshot::Receiver<()>)
    where
        F: FnOnce(WebSocketStream<TcpStream>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (ready_tx, ready_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let socket = accept_async(stream).await.unwrap();
            let _ = ready_tx.send(());
            handler(socket).await;
        });

        (url, ready_rx)
    }
}
