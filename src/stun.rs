use super::*;

use {
    bytecodec::{Decode, EncodeExt},
    stun_codec::{
        rfc5389::{attributes, methods::BINDING, Attribute},
        Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
    },
};

#[instrument(name = " STUN protocol", skip_all)]
pub async fn lookup_external_address(
    mut stream: impl AsyncWrite + AsyncBufRead + Unpin,
) -> Result<SocketAddr, ()> {
    // Send request
    let request = MessageEncoder::<Attribute>::new()
        .encode_into_bytes(Message::new(
            MessageClass::Request,
            BINDING,
            TransactionId::new([0; 12]),
        ))
        .expect("Failed to encode STUN request");
    stream
        .write_all(request.as_slice())
        .await
        .map_err(map_warn!("Failed to send request"))?;

    // Decode response
    let mut decoder = MessageDecoder::<Attribute>::new();
    let mut last_len = 0usize;
    loop {
        let buf = stream
            .fill_buf()
            .await
            .map_err(map_warn!("Failed to read from socket"))?;
        if last_len == buf.len() {
            return Err(warn!("Socket closed"));
        }
        last_len = buf.len();

        let consumed = decoder
            .decode(buf, bytecodec::Eos::new(false))
            .map_err(map_warn!("Failed to decode server response"))?;
        stream.consume(consumed);
        if decoder.is_idle() {
            break;
        }
    }
    let decoded = decoder
        .finish_decoding()
        .map_err(map_warn!("Failed to decode server response"))?
        .map_err(|err| warn!("Failed to decode server response {}", err.error()))?;

    let attrs = decoded;
    if let Some(attr) = attrs.get_attribute::<attributes::XorMappedAddress>() {
        return Ok(attr.address());
    }
    if let Some(attr) = attrs.get_attribute::<attributes::XorMappedAddress2>() {
        return Ok(attr.address());
    }
    if let Some(attr) = attrs.get_attribute::<attributes::MappedAddress>() {
        return Ok(attr.address());
    }

    warn!("Unnable to find address attribute in server response");
    println!("{:#?}", attrs);
    Err(())
}
