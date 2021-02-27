extern crate reqwest;
extern crate url;
extern crate hmac;
extern crate sha2;
extern crate base64;

use reqwest::Client;
use std::collections::HashMap;
use url::Url;

use sha2::Sha512;
use hmac::{Hmac, Mac, NewMac};

type HmacSha512 = Hmac<Sha512>;

pub struct PlateApi {
    client: reqwest::Client,
    public_key: String,
    secret_key: String,
}

impl PlateApi {
    pub fn new(public_key: String, secret_key: String) -> Self {
        PlateApi {
            client: Client::new(),
            public_key,
            secret_key
        }
    }

    pub fn get(&self, url: &str, params: &HashMap<String, String>) {
        // calculate hmac
        // TODO need to sort params

        let mut url = Url::parse_with_params(url, params).expect("url");
        url.query_pairs_mut().extend_pairs(params);
        
        // self.client.get()
    }

    // Signs the request with HMAC SHA512 
    fn sign(&self, signature_string: &str) {
        let mut mac = HmacSha512::new_varkey(&self.secret_key.as_bytes())
        .expect("hmac");

        mac.update(signature_string.as_bytes());
        let result = mac.finalize();

        let bytes = result.into_bytes();

        base64::encode(bytes);
    }


    fn signature_fields(method: &str, url: &Url, params: Option<&HashMap<String, String>>, date: &str) {
        let string = String::from(
            format!("{}\n{}\n{}\n{}\n{}",
            method, 
            url.host_str().expect("host"), 
            url.path(), 
            url.query().unwrap_or(""),
            date
        ));
    }

}