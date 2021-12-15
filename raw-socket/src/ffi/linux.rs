// Copyright (C) 2020 - Will Glozer. All rights reserved.

use libc::c_int;

pub const IPV6_CHECKSUM:     c_int = libc::IPV6_CHECKSUM;
pub const IPV6_RECVHOPLIMIT: c_int = 51;
pub const IPV6_HOPLIMIT:     c_int = 52;
pub const IPV6_RECVPATHMTU:  c_int = 60;
pub const IPV6_PATHMTU:      c_int = 61;
