#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    AwaitingClientHello,
    AwaitingClientFinish,
    Established,
    Closing,
}