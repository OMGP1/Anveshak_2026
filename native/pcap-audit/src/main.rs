//! Bounded classic-PCAP ingest. Stream mode feeds the existing passive decoder over stdout.
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn audit(reader: &mut impl Read) -> io::Result<(u64, u64)> {
    scan(reader, &mut io::sink(), false)
}

fn scan(reader: &mut impl Read, output: &mut impl Write, stream: bool) -> io::Result<(u64, u64)> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let (little, resolution) = match &header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, 1_000_000),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, 1_000_000),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, 1_000_000_000),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, 1_000_000_000),
        _ => return Err(invalid("Unsupported magic; only classic PCAP is supported")),
    };
    let u32_at = |bytes: &[u8]| {
        let value: [u8; 4] = bytes.try_into().unwrap();
        if little { u32::from_le_bytes(value) } else { u32::from_be_bytes(value) }
    };
    let version = if little { [2, 0, 4, 0] } else { [0, 2, 0, 4] };
    if header[4..8] != version { return Err(invalid("Unsupported PCAP version")); }
    let snaplen = u32_at(&header[16..20]);
    if snaplen == 0 || snaplen > 16 * 1024 * 1024 { return Err(invalid("Invalid snap length")); }
    if stream {
        output.write_all(b"SIH1")?;
        output.write_all(&u32_at(&header[20..24]).to_be_bytes())?;
    }
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut buffer = Vec::new();
    let mut previous = 0u64;
    loop {
        let mut record = [0u8; 16];
        match reader.read(&mut record[..1])? {
            0 => { output.flush()?; return Ok((packets, bytes)); }
            _ => reader.read_exact(&mut record[1..])?,
        }
        let seconds = u32_at(&record[..4]);
        let fraction = u32_at(&record[4..8]);
        let length = u32_at(&record[8..12]);
        let original = u32_at(&record[12..16]);
        if fraction >= resolution || length > snaplen || length > original {
            return Err(invalid("Invalid timestamp or packet length"));
        }
        let stamp = u64::from(seconds) * u64::from(resolution) + u64::from(fraction);
        if packets > 0 && stamp < previous { return Err(invalid("Non-monotonic packet timestamp")); }
        previous = stamp;
        buffer.resize(length as usize, 0);
        reader.read_exact(&mut buffer)?;
        if stream {
            let nanoseconds = u64::from(seconds) * 1_000_000_000
                + u64::from(fraction) * (1_000_000_000 / u64::from(resolution));
            output.write_all(&nanoseconds.to_be_bytes())?;
            output.write_all(&length.to_be_bytes())?;
            output.write_all(&buffer)?;
        }
        packets += 1;
        bytes += u64::from(length);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<_> = std::env::args_os().skip(1).collect();
    if paths.first().is_some_and(|p| p == "--stream") {
        if paths.len() != 2 { return Err("Usage: pcap-audit --stream FILE.pcap".into()); }
        scan(&mut BufReader::new(File::open(&paths[1])?), &mut BufWriter::new(io::stdout().lock()), true)?;
        return Ok(());
    }
    if paths.is_empty() { return Err("Usage: pcap-audit FILE.pcap [FILE.pcap ...]".into()); }
    for path in paths {
        let (packets, bytes) = audit(&mut BufReader::new(File::open(path)?))?;
        println!("{{\"packets\":{packets},\"captured_bytes\":{bytes},\"ok\":true}}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn capture() -> Vec<u8> {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        bytes.extend([0; 8]);
        bytes.extend(65535u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        for value in [1u32, 0, 4, 4] { bytes.extend(value.to_le_bytes()); }
        bytes.extend([1, 2, 3, 4]);
        bytes
    }
    #[test] fn valid() { assert_eq!(audit(&mut &capture()[..]).unwrap(), (1, 4)); }
    #[test] fn binary_stream_preserves_bytes_and_timestamp() {
        let mut out = Vec::new(); scan(&mut &capture()[..], &mut out, true).unwrap();
        assert_eq!(&out[..4], b"SIH1");
        assert_eq!(&out[4..8], &1u32.to_be_bytes());
        assert_eq!(&out[8..16], &1_000_000_000u64.to_be_bytes());
        assert_eq!(&out[16..20], &4u32.to_be_bytes());
        assert_eq!(&out[20..], &[1, 2, 3, 4]);
    }
    #[test] fn truncated_at_every_byte() {
        let bytes = capture();
        for length in 0..bytes.len() {
            if length != 24 { assert!(audit(&mut &bytes[..length]).is_err(), "length {length}"); }
        }
    }
    #[test] fn malformed_length() {
        let mut bytes = capture(); bytes[32..36].copy_from_slice(&65536u32.to_le_bytes());
        assert!(audit(&mut &bytes[..]).is_err());
    }
    #[test] fn invalid_timestamp() {
        let mut bytes = capture(); bytes[28..32].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(audit(&mut &bytes[..]).is_err());
    }
}
