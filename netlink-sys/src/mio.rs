use crate::Socket;
use std::os::unix::io::AsRawFd;

use mio::event::Source;
use mio::unix::SourceFd;

impl Source for Socket {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        let raw_fd = self.as_raw_fd();

        SourceFd(&raw_fd).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        let raw_fd = self.as_raw_fd();

        SourceFd(&raw_fd).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        let raw_fd = self.as_raw_fd();

        SourceFd(&raw_fd).deregister(registry)
    }
}
