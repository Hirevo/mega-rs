use std::io;
use std::pin::Pin;

use async_trait::async_trait;
use futures::io::AsyncRead;
use futures::TryStreamExt;
use json::Value;
use reqwest::Body;
use tokio_util::codec::{BytesCodec, FramedRead};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use url::Url;

use crate::commands::{Request, Response};
use crate::error::Error;
use crate::http::HttpClient;
use crate::{ClientState, ErrorCode};

#[async_trait]
impl HttpClient for reqwest::Client {
    async fn send_requests(
        &self,
        state: &ClientState,
        requests: &[Request],
    ) -> Result<Vec<Response>, Error> {
        let url = {
            let mut url = state.origin.join("/cs").unwrap();

            let mut qs = url.query_pairs_mut();
            qs.append_pair("id", state.id_counter.to_string().as_str());

            if let Some(session) = state.session.as_ref() {
                qs.append_pair("sid", session.sid.as_str());
            }

            qs.finish();
            drop(qs);

            url
        };

        let mut delay = state.min_retry_delay;
        for i in 0..state.max_retries {
            if i > 0 {
                tokio::time::sleep(delay).await;
                delay *= 2;
                // TODO: maybe add some small random jitter after the doubling.
                if delay > state.max_retry_delay {
                    delay = state.max_retry_delay;
                }
            }

            // dbg!(&requests);
            let request = self.post(url.clone()).json(requests).send();
            let maybe_response = if let Some(timeout) = state.timeout {
                let Ok(maybe_response) = tokio::time::timeout(timeout, request).await else {
                    // the timeout has been reached, let's retry.
                    continue;
                };
                maybe_response
            } else {
                request.await
            };

            let Ok(response) = maybe_response else {
                // this could be a network issue, let's retry.
                continue;
            };

            if !response.status().is_success() {
                // this could be a server error, let's retry.
                continue;
            }

            let Ok(response) = response.bytes().await else {
                // this could be a network issue, let's retry.
                continue;
            };

            // try to parse a request-level error first.
            if let Ok(code) = json::from_slice::<ErrorCode>(&response) {
                if code == ErrorCode::EAGAIN {
                    // this error code suggests we might succeed if retried, let's retry.
                    continue;
                }
                return Err(Error::from(code));
            }

            let responses: Vec<Value> = json::from_slice(&response)?;
            // dbg!(&responses);

            return requests
                .iter()
                .zip(responses)
                .map(|(request, response)| request.parse_response_data(response))
                .collect();
        }

        Err(Error::MaxRetriesReached)
    }

    async fn download(&self, url: Url) -> Result<Pin<Box<dyn AsyncRead>>, Error> {
        let stream = self
            .get(url)
            .send()
            .await?
            .bytes_stream()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err));

        Ok(Box::pin(stream.into_async_read()))
    }

    async fn upload(
        &self,
        url: Url,
        size: u64,
        body: Pin<Box<dyn AsyncRead + Send + Sync>>,
    ) -> Result<Option<String>, Error> {
        let stream = FramedRead::new(body.compat(), BytesCodec::new());
        let body = Body::wrap_stream(stream);
        let completion_handle = self
            .post(url)
            .header("content-length", size)
            .body(body)
            .send()
            .await?
            .text()
            .await?;
        Ok((!completion_handle.is_empty()).then_some(completion_handle))
    }
}
