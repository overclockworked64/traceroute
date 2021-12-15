// Copyright (C) 2020 - Will Glozer. All rights reserved.

use libc::c_int;

pub const IPV6_CHECKSUM:     c_int = 26;
pub const IPV6_RECVHOPLIMIT: c_int = 37;
pub const IPV6_HOPLIMIT:     c_int = 47;
pub const IPV6_RECVPATHMTU:  c_int = 43;
pub const IPV6_PATHMTU:      c_int = 44;
