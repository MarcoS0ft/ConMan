#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]

pub use bytes;

mod connector;
mod framed;
mod session;

pub use self::connector::*;
pub use self::framed::*;
// pub use self::session::*;

/// Callback for CredSSP network round-trips (Kerberos / NTLM).
///
/// Only required when the `credssp` feature is enabled.
#[cfg(feature = "credssp")]
pub trait NetworkClient {
    fn send(
        &mut self,
        network_request: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> impl Future<Output = ironrdp_connector::ConnectorResult<Vec<u8>>>;
}
