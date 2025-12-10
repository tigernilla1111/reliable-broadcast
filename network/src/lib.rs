pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

struct Interface {
    client: Client,
    listener: Listener,
}
/// Outgoing RPC requests
struct Client;
impl Client {
    fn send_rpc() {}
}

/// Incoming RPC requests
struct Listener;
impl Listener {
    fn start_listening() {}
}
