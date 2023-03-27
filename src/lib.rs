use base64::{engine::general_purpose, Engine as _};
use bytes::{BufMut, Bytes, BytesMut};
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(author, version)]
struct Cli {
    /// using get method
    #[arg(short, long)]
    get: bool,

    /// query domain name
    #[arg(short = 'n', long, default_value = "example.com")]
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
    #[arg(long, default_value = "https://localhost:8443/dns-query")]
    url: String,
}

#[derive(ValueEnum, Clone)]
enum DNSType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    PTR = 12,
    SOA = 6,
    NS = 2,
}

#[derive(ValueEnum, Clone)]
enum DNSClass {
    IN = 1,
}

pub fn run() {
    let cli = Cli::parse();
    println!("get: {:?}", cli.get);
    println!("domain_name: {:?}", cli.domain_name);
}

///
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

    let b = encode_query("example.com", DNSType::AAAA, DNSClass::IN);
    assert_eq!(
        "CAkBEAABAAAAAAAAB2V4YW1wbGUDY29tAAAcAAE",
        bytes_to_base64_encode(&b)
    );

    let b = encode_query("example.com", DNSType::A, DNSClass::IN);
    assert_eq!(
        "CAkBEAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE",
        bytes_to_base64_encode(&b)
    );
}
