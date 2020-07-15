use std::mem::transmute;

use libc::*;
use openssl::ssl::*;
use openssl::x509::verify::X509VerifyParamRef;

pub const X509_V_FLAG_USE_CHECK_TIME: c_ulong = 0x2;
pub const X509_V_FLAG_CRL_CHECK: c_ulong = 0x4;
pub const X509_V_FLAG_CRL_CHECK_ALL: c_ulong = 0x8;
pub const X509_V_FLAG_IGNORE_CRITICAL: c_ulong = 0x10;
pub const X509_V_FLAG_X509_STRICT: c_ulong = 0x20;
pub const X509_V_FLAG_ALLOW_PROXY_CERTS: c_ulong = 0x40;
pub const X509_V_FLAG_POLICY_CHECK: c_ulong = 0x80;
pub const X509_V_FLAG_EXPLICIT_POLICY: c_ulong = 0x100;
pub const X509_V_FLAG_INHIBIT_ANY: c_ulong = 0x200;
pub const X509_V_FLAG_INHIBIT_MAP: c_ulong = 0x400;
pub const X509_V_FLAG_NOTIFY_POLICY: c_ulong = 0x800;
pub const X509_V_FLAG_EXTENDED_CRL_SUPPORT: c_ulong = 0x1000;
pub const X509_V_FLAG_USE_DELTAS: c_ulong = 0x2000;
pub const X509_V_FLAG_CHECK_SS_SIGNATURE: c_ulong = 0x4000;
pub const X509_V_FLAG_TRUSTED_FIRST: c_ulong = 0x8000;
pub const X509_V_FLAG_SUITEB_128_LOS_ONLY: c_ulong = 0x10000;
pub const X509_V_FLAG_SUITEB_192_LOS: c_ulong = 0x20000;
pub const X509_V_FLAG_SUITEB_128_LOS: c_ulong = 0x30000;
pub const X509_V_FLAG_PARTIAL_CHAIN: c_ulong = 0x80000;

const X509_V_FLAG_POLICY_MASK: c_ulong = X509_V_FLAG_POLICY_CHECK
    | X509_V_FLAG_EXPLICIT_POLICY
    | X509_V_FLAG_INHIBIT_ANY
    | X509_V_FLAG_INHIBIT_MAP;

pub trait TransPublic {
    type Public;

    fn trans_public(&mut self) -> &mut Self::Public;
}

pub trait SetFlags {
    fn set_flags(&mut self, flags: c_ulong);
}

impl SetFlags for X509VerifyParamRef {
    fn set_flags(&mut self, flags: c_ulong) {
        #[repr(C)]
        struct X509VerifyParamHeader {
            pub name: *mut c_char,
            pub check_time: time_t,
            pub inh_flags: c_ulong,
            pub flags: c_ulong,
        }

        let x509_vpm_header: &mut X509VerifyParamHeader = unsafe { transmute(self) };
        x509_vpm_header.flags |= flags;
        if flags & X509_V_FLAG_POLICY_MASK != 0 {
            x509_vpm_header.flags |= X509_V_FLAG_POLICY_CHECK;
        }
    }
}

pub struct PublicConnectConfiguration {
    pub ssl: Ssl,
    pub sni: bool,
    pub verify_hostname: bool,
}

impl TransPublic for ConnectConfiguration {
    type Public = PublicConnectConfiguration;

    fn trans_public(&mut self) -> &mut Self::Public {
        unsafe { transmute(self) }
    }
}
