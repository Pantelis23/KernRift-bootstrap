//! Pre-assembled runtime blobs for native hostexe emission.
//!
//! Each submodule provides a `BLOB: RuntimeBlob` containing hand-assembled machine
//! code that implements `_start` and the nine `__kr_*` host functions for a
//! specific OS + architecture combination.

pub mod linux_x86_64;
pub mod linux_aarch64;
pub mod macos_x86_64;
pub mod macos_aarch64;
pub mod windows_x86_64;
pub mod windows_aarch64;

/// A pre-assembled runtime blob for a specific OS+arch combination.
pub struct RuntimeBlob {
    /// Machine code bytes followed by a 24-byte data area:
    ///   [data_start + 0]:  envp          (u64, set by _start)
    ///   [data_start + 8]:  heap_ptr      (u64, managed by __kr_alloc)
    ///   [data_start + 16]: heap_remaining (u64, managed by __kr_alloc)
    pub code: &'static [u8],
    /// Symbol table: (name, byte_offset_within_code).
    pub symbols: &'static [(&'static str, u32)],
    /// Byte offset within `code` of the 4-byte rel32 displacement in the
    /// `call main` instruction inside `_start`. The hostexe linker patches
    /// this to: `user_main_offset - (user_code_len + main_call_fixup + 4)`.
    pub main_call_fixup: u32,
    /// (Windows only) Byte offset within `code` of the 8-byte `iat_base`
    /// data slot.  The hostexe linker writes the IAT virtual address here so
    /// the runtime can locate Win32 API function pointers at load time.
    /// `None` for non-Windows blobs.
    pub iat_base_data_offset: Option<u32>,
}

impl RuntimeBlob {
    /// Look up a symbol's byte offset within the blob.
    pub fn symbol_offset(&self, name: &str) -> Option<u32> {
        self.symbols
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, off)| *off)
    }
}
