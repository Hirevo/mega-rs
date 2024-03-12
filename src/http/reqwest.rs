use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use futures::io::AsyncRead;
use futures::TryStreamExt;
use json::Value;
use reqwest::Body;
use secrecy::ExposeSecret;
use tokio_util::codec::{BytesCodec, FramedRead};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use url::Url;

use crate::error::{Error, Result};
use crate::http::HttpClient;
use crate::protocol::commands::{Request, Response};
use crate::{ClientState, ErrorCode};

#[async_trait]
impl HttpClient for reqwest::Client {
    #[tracing::instrument(skip(self, state, query_params))]
    async fn send_requests(
        &self,
        state: &ClientState,
        requests: &[Request],
        query_params: &[(&str, &str)],
    ) -> Result<Vec<Response>> {
        tracing::trace!(?self, ?state, "preparing MEGA request");

        let url = {
            let mut url = state.origin.join("/cs")?;

            let mut qs = url.query_pairs_mut();
            let id_counter = state.id_counter.fetch_add(1, Ordering::SeqCst);
            qs.append_pair("id", id_counter.to_string().as_str());

            if let Some(session) = state.session.as_ref() {
                qs.append_pair("sid", session.expose_secret().sid.as_str());
            }

            qs.extend_pairs(query_params);

            qs.finish();
            drop(qs);

            url
        };

        let mut delay = state.min_retry_delay;
        for attempt in 1..=state.max_retries {
            if attempt > 1 {
                tracing::debug!(?delay, "sleeping for exponential backoff before retrying");
                tokio::time::sleep(delay).await;
                delay *= 2;
                // TODO: maybe add some small random jitter after the doubling.
                if delay > state.max_retry_delay {
                    delay = state.max_retry_delay;
                }
            }

            // dbg!(&requests);
            tracing::debug!(?attempt, "starting MEGA request attempt");

            let request = async {
                self.post(url.clone())
                    .json(requests)
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await
            };

            let maybe_response = if let Some(timeout) = state.timeout {
                tracing::debug!(?timeout, "attempting MEGA request with timeout");
                let Ok(maybe_response) = tokio::time::timeout(timeout, request).await else {
                    // the timeout has been reached, let's retry.
                    tracing::debug!("MEGA request has timed out");
                    continue;
                };
                maybe_response
            } else {
                request.await
            };

            let response = match maybe_response {
                Ok(response) => response,
                Err(error) => {
                    // this could be a network issue, let's retry.
                    tracing::error!(?error, "`reqwest` error when making MEGA request");
                    continue;
                }
            };

            // try to parse a request-level error first.
            if let Ok(code) = json::from_slice::<ErrorCode>(&response) {
                if code == ErrorCode::EAGAIN {
                    // this error code suggests we might succeed if retried, let's retry.
                    tracing::debug!("received `EAGAIN` error code from MEGA");
                    continue;
                }
                if code != ErrorCode::OK {
                    tracing::error!(?code, "received error code from MEGA");
                }
                return Err(Error::from(code));
            }

            // dbg!(&responses);
            let responses: Vec<Value> = match json::from_slice(&response) {
                Ok(responses) => responses,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "could not deserialize MEGA response as a JSON array",
                    );
                    return Err(error.into());
                }
            };

            return requests
                .iter()
                .zip(responses)
                .map(|(request, response)| request.parse_response_data(response))
                .collect();
        }

        tracing::error!("maximum amount of retries reached, cancelling MEGA request");

        Err(Error::MaxRetriesReached)
    }

    async fn get(&self, url: Url) -> Result<Pin<Box<dyn AsyncRead + Send>>> {
        let stream = self
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes_stream()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err));

        Ok(Box::pin(stream.into_async_read()))
    }

    async fn post(
        &self,
        url: Url,
        body: Pin<Box<dyn AsyncRead + Send + Sync>>,
        content_length: Option<u64>,
    ) -> Result<Pin<Box<dyn AsyncRead + Send>>> {
        let stream = FramedRead::new(body.compat(), BytesCodec::new());
        let body = Body::wrap_stream(stream);
        let stream = {
            let mut builder = self.post(url);

            if let Some(content_length) = content_length {
                builder = builder.header("content-length", content_length);
            }

            builder
                .body(body)
                .send()
                .await?
                .error_for_status()?
                .bytes_stream()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        };

        Ok(Box::pin(stream.into_async_read()))
    }
}
