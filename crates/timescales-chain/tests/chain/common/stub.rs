//! A stub JSON-RPC server: replies to each method from a script (recorded
//! responses, or HTTP failures) and keeps every request it received.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use parking_lot::Mutex;
use serde_json::Value;
use tokio::task::JoinHandle;

/// One scripted reply.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A JSON-RPC response object. Its `id` becomes the request's.
    Rpc(Value),
    /// The status with an empty body. 429 carries `Retry-After: 0`.
    Status(u16),
    /// Status 200 with these bytes as the body.
    Raw(Vec<u8>),
    /// Waits, then replies.
    Slow(Duration, Box<Reply>),
}

#[derive(Default)]
struct Script {
    replies: HashMap<String, VecDeque<Reply>>,
    any: VecDeque<Reply>,
    requests: Vec<Value>,
}

pub struct Stub {
    pub url: String,
    script: Arc<Mutex<Script>>,
    task: JoinHandle<()>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Stub {
    pub async fn start() -> Self {
        let script = Arc::new(Mutex::new(Script::default()));
        let app = Router::new()
            .route("/", post(handle))
            .with_state(script.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, script, task }
    }

    /// Queues `reply` for the next request of `method`.
    pub fn reply(&self, method: &str, reply: Reply) {
        self.script
            .lock()
            .replies
            .entry(method.to_owned())
            .or_default()
            .push_back(reply);
    }

    /// Queues `reply` for the next request of a method without its own
    /// queued reply.
    pub fn reply_any(&self, reply: Reply) {
        self.script.lock().any.push_back(reply);
    }

    /// Every request received, in order.
    pub fn requests(&self) -> Vec<Value> {
        self.script.lock().requests.clone()
    }

    /// The `params` of every request of `method`.
    pub fn params(&self, method: &str) -> Vec<Value> {
        self.requests()
            .into_iter()
            .filter(|r| r["method"] == method)
            .map(|r| r["params"].clone())
            .collect()
    }
}

async fn handle(State(script): State<Arc<Mutex<Script>>>, body: Bytes) -> Response {
    let request: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "not JSON").into_response(),
    };
    let reply = {
        let mut s = script.lock();
        s.requests.push(request.clone());
        let method = request["method"].as_str().unwrap_or_default().to_owned();
        let queued = s.replies.get_mut(&method).and_then(VecDeque::pop_front);
        queued.or_else(|| s.any.pop_front())
    };
    match reply {
        Some(reply) => respond(reply, &request["id"]).await,
        None => (StatusCode::INTERNAL_SERVER_ERROR, "no scripted reply").into_response(),
    }
}

async fn respond(mut reply: Reply, id: &Value) -> Response {
    loop {
        match reply {
            Reply::Slow(delay, inner) => {
                tokio::time::sleep(delay).await;
                reply = *inner;
            }
            Reply::Rpc(mut v) => {
                v["id"] = id.clone();
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_vec(&v).unwrap(),
                )
                    .into_response();
            }
            Reply::Status(429) => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, "0")],
                    Vec::new(),
                )
                    .into_response();
            }
            Reply::Status(code) => {
                return StatusCode::from_u16(code).unwrap().into_response();
            }
            Reply::Raw(body) => {
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response();
            }
        }
    }
}
