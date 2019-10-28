use core::fmt::{self, Display};
use failure::{Backtrace, Context, Fail};

#[derive(Debug)]
pub struct EncodeError {
    inner: Context<String>,
}

impl Fail for EncodeError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl From<&'static str> for EncodeError {
    fn from(msg: &'static str) -> Self {
        EncodeError {
            inner: Context::new(msg.into()),
        }
    }
}

impl From<String> for EncodeError {
    fn from(msg: String) -> Self {
        EncodeError {
            inner: Context::new(msg),
        }
    }
}

impl From<Context<String>> for EncodeError {
    fn from(inner: Context<String>) -> Self {
        EncodeError { inner }
    }
}

impl From<Context<&'static str>> for EncodeError {
    fn from(inner: Context<&'static str>) -> Self {
        EncodeError {
            inner: inner.map(|s| s.to_string()),
        }
    }
}

#[derive(Debug)]
pub struct DecodeError {
    inner: Context<String>,
}

impl Fail for DecodeError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl From<&'static str> for DecodeError {
    fn from(msg: &'static str) -> Self {
        DecodeError {
            inner: Context::new(msg.into()),
        }
    }
}

impl From<String> for DecodeError {
    fn from(msg: String) -> Self {
        DecodeError {
            inner: Context::new(msg),
        }
    }
}

impl From<Context<String>> for DecodeError {
    fn from(inner: Context<String>) -> Self {
        DecodeError { inner }
    }
}

impl From<Context<&'static str>> for DecodeError {
    fn from(inner: Context<&'static str>) -> Self {
        DecodeError {
            inner: inner.map(|s| s.to_string()),
        }
    }
}
