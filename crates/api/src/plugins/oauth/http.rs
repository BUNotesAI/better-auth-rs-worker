use std::collections::HashMap;

use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, HttpMethod, OAuthHttpClient, OAuthHttpRequest, OAuthHttpResponse,
};

#[derive(Debug, Clone, Default)]
pub struct ReqwestOAuthHttpClient {
    client: reqwest::Client,
}

impl ReqwestOAuthHttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg_attr(feature = "local-futures", async_trait(?Send))]
#[cfg_attr(not(feature = "local-futures"), async_trait)]
impl OAuthHttpClient for ReqwestOAuthHttpClient {
    async fn send(&self, request: OAuthHttpRequest) -> AuthResult<OAuthHttpResponse> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Options => reqwest::Method::OPTIONS,
            HttpMethod::Head => reqwest::Method::HEAD,
        };

        let mut builder = self.client.request(method, &request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| AuthError::internal(format!("OAuth HTTP request failed: {}", e)))?;
        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|e| AuthError::internal(format!("OAuth HTTP response read failed: {}", e)))?
            .to_vec();

        Ok(OAuthHttpResponse {
            status,
            headers,
            body,
        })
    }
}
