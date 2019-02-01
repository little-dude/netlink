use std::mem;
use std::ptr::NonNull;

use crate::sock_diag::SkMemInfo;
use crate::{DecodeError, Parseable};

impl<T: AsRef<[u8]>> Parseable<SkMemInfo> for T {
    fn parse(&self) -> Result<SkMemInfo, DecodeError> {
        let data = self.as_ref();

        if data.len() >= mem::size_of::<SkMemInfo>() {
            Ok(unsafe {
                NonNull::new_unchecked(data.as_ptr() as *mut u8)
                    .cast::<SkMemInfo>()
                    .as_ptr()
                    .read()
            })
        } else {
            Err(format!(
                "buffer size is {}, whereas a buffer is at least {} long",
                data.len(),
                mem::size_of::<SkMemInfo>()
            )
            .into())
        }
    }
}
