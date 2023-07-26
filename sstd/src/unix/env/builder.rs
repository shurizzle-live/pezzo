use core::{hash::BuildHasher, marker::PhantomData};

use crate::{env::VarName, ffi::CStr};
use alloc_crate::vec::Vec;
use hashbrown::{hash_map::DefaultHashBuilder, raw::RawTable};

struct Var {
    total_len: usize,
    base: *mut u8,
    key_len: usize,
}

impl Var {
    pub fn key(&self) -> &VarName {
        unsafe { VarName::from_raw_parts(self.base, self.key_len) }
    }

    pub fn value(&self) -> Option<&CStr> {
        if self.is_none() {
            None
        } else {
            unsafe {
                Some(CStr::from_bytes_with_nul_unchecked(
                    core::slice::from_raw_parts(self.base, self.total_len)
                        .get_unchecked((self.key_len + 1)..),
                ))
            }
        }
    }

    pub fn set_value(&mut self, v: &CStr) {
        unsafe {
            let mut buf = Vec::from_raw_parts(self.base, self.total_len, self.total_len);
            let v = v.to_bytes_with_nul();
            if self.is_some() {
                buf.set_len(self.key_len + 1);
                buf.reserve_exact(v.len());
            } else {
                buf.reserve_exact(v.len() + 1);
                buf.push(b'=');
            }
            buf.extend_from_slice(v);
            buf.shrink_to_fit();

            self.total_len = buf.len();
            self.base = buf.as_mut_ptr();
            core::mem::forget(buf);
        }
    }

    pub fn unset_value(&mut self) {
        unsafe {
            if self.is_some() {
                let mut buf = Vec::from_raw_parts(self.base, self.total_len, self.total_len);
                buf.set_len(self.key_len);
                buf.shrink_to_fit();
                self.total_len = buf.len();
                self.base = buf.as_mut_ptr();
                core::mem::forget(buf);
            }
        }
    }

    #[inline]
    pub fn is_some(&self) -> bool {
        self.total_len != self.key_len
    }

    #[inline]
    pub fn is_none(&self) -> bool {
        self.total_len == self.key_len
    }

    pub fn some(k: &VarName, v: &CStr) -> Self {
        let total_len = k.as_bytes().len() + 1 + v.to_bytes_with_nul().len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(k.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(v.to_bytes_with_nul());
        buf.shrink_to_fit();
        assert_eq!(buf.len(), total_len);
        let base = buf.as_mut_ptr();
        let key_len = k.as_bytes().len();
        core::mem::forget(buf);

        Self {
            total_len,
            base,
            key_len,
        }
    }

    pub fn none(k: &VarName) -> Self {
        let mut buf = Vec::with_capacity(k.as_bytes().len());
        buf.extend_from_slice(k.as_bytes());
        buf.shrink_to_fit();
        let total_len = buf.len();
        let key_len = k.as_bytes().len();
        assert_eq!(total_len, key_len);
        let base = buf.as_mut_ptr();
        core::mem::forget(buf);

        Self {
            total_len,
            base,
            key_len,
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.base
    }
}

impl Drop for Var {
    fn drop(&mut self) {
        drop(unsafe { Vec::from_raw_parts(self.base, self.total_len, self.total_len) });
    }
}

pub struct EnvironmentBuilder<H: BuildHasher = DefaultHashBuilder> {
    clean: bool,
    hash_builder: H,
    table: RawTable<Var>,
}

pub struct EnvironmentCapture<'a> {
    list: Vec<*const u8>,
    _life: PhantomData<&'a ()>,
}

impl EnvironmentBuilder<DefaultHashBuilder> {
    pub fn new() -> Self {
        Self {
            clean: false,
            hash_builder: DefaultHashBuilder::default(),
            table: RawTable::new(),
        }
    }

    pub fn insert<K: AsRef<VarName>, V: AsRef<CStr>>(&mut self, k: K, v: V) {
        let k = k.as_ref();
        let v = v.as_ref();
        let hash = self.hash_builder.hash_one(k);

        if let Some(var) = self.table.get_mut(hash, |var| var.key() == k) {
            var.set_value(v);
        } else {
            let var = Var::some(k, v);
            self.table
                .insert_entry(hash, var, |var| self.hash_builder.hash_one(var.key()));
        }
    }

    pub fn remove<K: AsRef<VarName>>(&mut self, k: K) {
        let k = k.as_ref();
        let hash = self.hash_builder.hash_one(k);

        if let Some(var) = self.table.get_mut(hash, |var| var.key() == k) {
            var.unset_value();
        } else {
            let var = Var::none(k);
            self.table
                .insert_entry(hash, var, |var| self.hash_builder.hash_one(var.key()));
        }
    }

    pub fn get<K: AsRef<VarName>>(&self, k: K) -> Option<&CStr> {
        let k = k.as_ref();
        let hash = self.hash_builder.hash_one(k);

        if let Some(var) = self.table.get(hash, |var| var.key() == k) {
            return var.value();
        }

        if self.clean {
            return None;
        }

        crate::env::var(k)
    }

    pub fn capture(&self) -> EnvironmentCapture<'_> {
        let mut res = Vec::new();

        unsafe {
            for var in self.table.iter() {
                let var = var.as_ref();
                if var.is_some() {
                    res.push(var.as_ptr());
                }
            }

            if !self.clean {
                for (name, _) in crate::env::vars() {
                    let hash = self.hash_builder.hash_one(name);
                    if self.table.get(hash, |var| var.key() == name).is_none() {
                        res.push(name.as_ptr());
                    }
                }
            }
        }

        res.push(core::ptr::null());

        EnvironmentCapture {
            list: res,
            _life: PhantomData,
        }
    }

    pub fn clean(&mut self, value: bool) {
        self.clean = value;
    }
}

impl EnvironmentCapture<'_> {
    pub fn as_ptr(&self) -> *const *const u8 {
        self.list.as_ptr()
    }
}

impl<'a> core::fmt::Debug for EnvironmentCapture<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        struct Iter<'a>(*const *const u8, PhantomData<&'a ()>);
        impl<'a> Iterator for Iter<'a> {
            type Item = &'a CStr;

            fn next(&mut self) -> Option<Self::Item> {
                unsafe {
                    if (*self.0).is_null() {
                        None
                    } else {
                        let res = CStr::from_ptr((*self.0).cast());
                        self.0 = self.0.add(1);
                        Some(res)
                    }
                }
            }
        }

        f.debug_list()
            .entries(Iter(self.as_ptr(), PhantomData))
            .finish()
    }
}

impl Default for EnvironmentBuilder<DefaultHashBuilder> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
