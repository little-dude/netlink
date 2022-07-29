// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    ReportMessageBuffer,
    UserReport,
    UserReportBuffer,
    XfrmAttrs,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct ReportMessage {
    pub report: UserReport,
    pub nlas: Vec<XfrmAttrs>
}

impl Emitable for ReportMessage {
    fn buffer_len(&self) -> usize {
        self.report.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.report.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.report.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<ReportMessageBuffer<&'a T>> for ReportMessage {
    fn parse(buf: &ReportMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let report = UserReport::parse(&UserReportBuffer::new(&buf.report()))
            .context("failed to parse monitor acquire message info")?;
        Ok(ReportMessage {
            report,
            nlas: Vec::<XfrmAttrs>::parse(buf).context("failed to parse monitor report message NLAs")?
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<ReportMessageBuffer<&'a T>> for Vec<XfrmAttrs> {
    fn parse(buf: &ReportMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = vec![];
        for nla_buf in buf.nlas() {
            nlas.push(XfrmAttrs::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}
