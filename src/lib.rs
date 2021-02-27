extern crate reqwest;
extern crate url;
extern crate hmac;
extern crate sha2;
extern crate base64;
extern crate chrono;

use reqwest::blocking::Client;
use std::collections::BTreeMap;
use url::Url;

use sha2::Sha512;
use hmac::{Hmac, Mac, NewMac};
use chrono::{DateTime, Utc};
use std::time::SystemTime;
use reqwest::header::*;

type HmacSha512 = Hmac<Sha512>;

pub struct PlateApi {
    client: reqwest::blocking::Client,
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

    // A Binary Search Tree is ordered by default. (see https://doc.rust-lang.org/beta/std/collections/struct.BTreeMap.html)
    pub fn get(&self, url: &str, params: &BTreeMap<String, String>) -> reqwest::blocking::Response {
        // let url = Url::parse_with_params(url, params).expect("url");
        let url = Url::parse(url).expect("url");

        dbg!(&url);

        let system_time = SystemTime::now();
        let datetime: DateTime<Utc> = system_time.into();
        let datetime = datetime.format("%a, %d %b %Y %T GMT");
        let signature = self.sign(PlateApi::signature_fields("GET", &url, &datetime.to_string()));

        let req = self.client
            .get(url)
            .header("Date", format!("{}", datetime))
            .header(AUTHORIZATION, format!("hmac {}:{}", self.public_key, signature))
            .build()
            .expect("request");
        
        dbg!(&req);
        self.client.execute(req).expect("request execution")
            
        // self.client.execute()

        // dbg!(&req);
    }

    // Signs the request with HMAC SHA512 
    fn sign(&self, signature_string: String) -> String {
        let mut mac = HmacSha512::new_varkey(&self.secret_key.as_bytes())
        .expect("hmac");
        mac.update(signature_string.as_bytes());

        let result = mac.finalize();
        let bytes = result.into_bytes();

        base64::encode(bytes)
    }


    fn signature_fields(method: &str, url: &Url, date: &str) -> String {
        let string = String::from(
            format!("{}\n{}\n{}\n{}\n{}",
            method, 
            url.host_str().expect("host"), 
            url.path(), 
            url.query().unwrap_or(""),
            date
        ));

        dbg!(&string);

        string
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn string_signing() {
        let client = PlateApi::new("mypublickey".to_string(), "mysecretkey".to_string());
        let mut bmap = BTreeMap::new();
        bmap.insert("paginate_amount", "10");
        bmap.insert("paginate_page", "2");

        let url = Url::parse_with_params("https://www.startwithplate.com/api/v2/partners/15/sites", &bmap).expect("Url");
        let signed_string = client.sign(PlateApi::signature_fields("GET", &url, "Sun, 06 Nov 1994 08:49:37 GMT"));

        assert_eq!(
            signed_string, 
            String::from("FOjhvBsNceYeVNAJtneSLUeYbNO133Gj1sx+aEu7I8A2ixH3VyYpc6PtxGDGVzpG1EPrDaL7sgurV2Q0+8BHDQ==")
        );
    }

    #[test]
    fn it_works() {
        let client = PlateApi::new("test".to_string(), "test".to_string());
        let mut map = BTreeMap::new();
        // map.insert("site_id".to_string(), "20".to_string());
        // map.insert("arie".to_string(), "1".to_string());

        let res = client.get("https://www.startwithplate.com/api/v2/sites/754/posts", &map);
        dbg!(&res);

        let json = res.text().expect("text");
        dbg!(json);

        assert_eq!(2 + 2, 4);
    }
}