// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(any(test, feature = "test-util")), no_std)]

//! `rsk-fs` — ISO-7816 file API over a backend-agnostic `Storage`: file contents
//! are key/value pairs keyed by 16-bit FID. On device the backend is
//! `sequential-storage` over embassy-rp flash (provided by `firmware`); tests use
//! a RAM backend. File metadata (type/ACL/parent) comes from a static table.

pub mod fs;
pub mod sealed;
pub mod storage;

pub use fs::{FileDesc, Fs};
pub use sealed::{KeyFid, Sealed};
pub use storage::Storage;

// ---- file types ----
pub const FILE_TYPE_NOT_KNOWN: u8 = 0x00;
pub const FILE_TYPE_DF: u8 = 0x04;
pub const FILE_TYPE_INTERNAL_EF: u8 = 0x02;
pub const FILE_TYPE_WORKING_EF: u8 = 0x01;
pub const FILE_TYPE_BSO: u8 = 0x10;
pub const FILE_PERSISTENT: u8 = 0x20;
pub const FILE_DATA_FLASH: u8 = 0x40;
pub const FILE_DATA_FUNC: u8 = 0x80;

// ---- EF structures ----
pub const FILE_EF_UNKNOWN: u8 = 0x00;
pub const FILE_EF_TRANSPARENT: u8 = 0x01;
pub const FILE_EF_LINEAR_FIXED: u8 = 0x02;
pub const FILE_EF_LINEAR_VARIABLE: u8 = 0x04;
pub const FILE_EF_CYCLIC: u8 = 0x06;

// ---- ACL operations (indices into FileDesc::acl) ----
pub const ACL_OP_DELETE_SELF: u8 = 0x00;
pub const ACL_OP_CREATE_DF: u8 = 0x01;
pub const ACL_OP_CREATE_EF: u8 = 0x02;
pub const ACL_OP_DELETE_CHILD: u8 = 0x03;
pub const ACL_OP_WRITE: u8 = 0x04;
pub const ACL_OP_UPDATE_ERASE: u8 = 0x05;
pub const ACL_OP_READ_SEARCH: u8 = 0x06;

/// The metadata side-store EF.
pub const EF_META: u16 = 0xE010;

/// Max number of dynamic (runtime-created) files.
pub const MAX_DYNAMIC_FILES: usize = 256;
