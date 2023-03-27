use base64::{engine::general_purpose, Engine as _};
use bytes::{BufMut, Bytes, BytesMut};
use clap::{Parser, ValueEnum};
use reqwest::{blocking::Client, blocking::RequestBuilder, header::HeaderMap};

static DEFAULT_DOMAIN_NAME: &'static str = "example.com";
static DEFAULT_QUERY_URL: &'static str = "https://localhost:8443/dns-query";

#[derive(Parser)]
#[command(author, version)]
pub struct Args {
    /// using get method
    #[arg(short, long)]
    get: bool,

    /// query domain name
    #[arg(short = 'n', long, default_value=DEFAULT_DOMAIN_NAME)]
    domain_name: String,

    /// choose a dns type
    #[arg(short = 't', long, value_enum)]
    domain_type: DNSType,

    /// choose a dns class
    #[arg(short = 'c', long, value_enum)]
    domain_class: DNSClass,

    /// should show response body
    #[arg(long = "body")]
    show_resp_body: bool,

    /// dns-over-http query url
    #[arg(long, default_value=DEFAULT_QUERY_URL)]
    url: String,
}

#[derive(ValueEnum, Clone, Copy)]
enum DNSType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    PTR = 12,
    SOA = 6,
    NS = 2,
}

#[derive(ValueEnum, Clone, Copy)]
enum DNSClass {
    IN = 1,
}

pub fn get_args() -> Args {
    Args::parse()
}

pub fn run(args: Args) {
    let dns_msg = encode_query(&args.domain_name, args.domain_type, args.domain_class);

    let req = build_request(&args, dns_msg);

    let res = req.send().expect("send request");
    if args.show_resp_body {
        println!("{:?}", res.text().expect("parse response text"));
    }
}

/// build a ready http request(get/post) without sending
fn build_request(args: &Args, dns_msg: Bytes) -> RequestBuilder {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/dns-message".parse().unwrap());
    let client = Client::builder().default_headers(headers).build().unwrap();

    if args.get {
        let dns_msg = bytes_to_base64_encode(&dns_msg);
        let url = format!("{}?dns={}", args.url.as_str(), dns_msg);
        client.get(url)
    } else {
        client.post(args.url.as_str()).body(dns_msg)
    }
}

/// encode DNS Wireformat
fn encode_query(fqdn: &str, t: DNSType, c: DNSClass) -> Bytes {
    let mut buf = BytesMut::new();

    // construct a dns header
    // TODO: use random hex instead of a fixed one
    // reqId
    buf.put_u16(0x0809);
    // QR = 0 (query)
    // OPCODE = 0 (standard query)
    // AA ignored
    // TC = 0 (not truncated)
    // RD = 1 (recursion desired)
    buf.put_u8((0 << 7) | (0 << 3) | (0 << 1) | 1);
    // RA ignored
    // Z = 0 (reserved)
    // AD = 0
    // CD = 1
    // RCODE ignored
    buf.put_u8(1 << 4);
    // QDCOUNT = 1
    buf.put_u8(0);
    buf.put_u8(1);
    // ANCOUNT = 0
    buf.put_u8(0);
    buf.put_u8(0);
    // NSCOUNT = 0
    buf.put_u8(0);
    buf.put_u8(0);
    // ARCOUNT = 0
    buf.put_u8(0);
    buf.put_u8(0);

    // construct the dns query
    // qname
    // TODO: validate str
    let labels: Vec<&str> = fqdn.split('.').collect();
    for l in labels {
        // fill len
        buf.put_u8(l.len() as u8);
        // fill byte array
        buf.put_slice(l.as_bytes());
    }
    // placeholder
    buf.put_u8(0);
    // qtype
    let t = t as u16;
    buf.put_u16(t);
    // qclass
    let c = c as u16;
    buf.put_u16(c);
    buf.freeze()
}

fn bytes_to_base64_encode(b: &Bytes) -> String {
    general_purpose::STANDARD_NO_PAD.encode(b)
}

#[test]
fn test_encode_query() {
    let b = encode_query("baidu.com", DNSType::A, DNSClass::IN);
    assert_eq!(
        "CAkBEAABAAAAAAAABWJhaWR1A2NvbQAAAQAB",
        bytes_to_base64_encode(&b)
    );

    let b = encode_query(DEFAULT_DOMAIN_NAME, DNSType::AAAA, DNSClass::IN);
    assert_eq!(
        "CAkBEAABAAAAAAAAB2V4YW1wbGUDY29tAAAcAAE",
        bytes_to_base64_encode(&b)
    );

    let b = encode_query(DEFAULT_DOMAIN_NAME, DNSType::A, DNSClass::IN);
    assert_eq!(
        "CAkBEAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE",
        bytes_to_base64_encode(&b)
    );
}

#[test]
fn test_build_request() {
    fn bytes_to_base64_decode(b: &str) -> Bytes {
        let b = general_purpose::STANDARD_NO_PAD.decode(b).unwrap();
        Bytes::from(b)
    }
    // generate a dns msg for testing
    let dns_msg = bytes_to_base64_decode("CAkBEAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE");

    // get method, normal url
    let args = Args {
        get: true,
        domain_name: DEFAULT_DOMAIN_NAME.to_owned(),
        domain_type: DNSType::A,
        domain_class: DNSClass::IN,
        show_resp_body: true,
        url: DEFAULT_QUERY_URL.to_owned(),
    };
    let req = build_request(&args, dns_msg.clone());

    // get method, invalid url
    let args = Args {
        get: true,
        domain_name: DEFAULT_DOMAIN_NAME.to_owned(),
        domain_type: DNSType::A,
        domain_class: DNSClass::IN,
        show_resp_body: true,
        url: "sdkl".to_owned(),
    };
    let req = build_request(&args, dns_msg.clone());
}
