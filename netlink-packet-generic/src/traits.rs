/// Provide the definition for generic netlink family
///
/// Your payload type should implement this trait to make the whole message serializable.
///
/// If you are looking for an example implementation, you can refer to the
/// [`crate::ctrl`] module.
pub trait GenlFamily {
    /// Return the unique family name
    ///
    /// Used to lookup the dynamically assigned ID
    fn family_name(&self) -> &'static str;

    /// Return the assigned family ID
    ///
    /// # Note
    /// The implementation of generic family should assign the ID to `GENL_ID_GENERATE` (0x0).
    /// So the controller can dynamically assign the family ID.
    ///
    /// Regarding to the reason above, you should not have to implement the function
    /// unless the family uses the static ID.
    fn family_id(&self) -> u16 {
        0
    }

    /// Return the command type of the message
    fn command(&self) -> u8;

    /// Indicate the protocol version
    fn version(&self) -> u8;
}
