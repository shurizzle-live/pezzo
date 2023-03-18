use std::{
    cmp::Ordering,
    ffi::{CStr, CString},
};

pub trait OrdCStr {
    fn cmp(&self, other: &CStr) -> Ordering;
}

impl<'a, T: OrdCStr + ?Sized> OrdCStr for &'a T {
    #[inline]
    fn cmp(&self, other: &CStr) -> Ordering {
        T::cmp(*self, other)
    }
}

impl OrdCStr for CStr {
    #[inline]
    fn cmp(&self, other: &CStr) -> Ordering {
        Ord::cmp(self, other)
    }
}

impl OrdCStr for CString {
    #[inline]
    fn cmp(&self, other: &CStr) -> Ordering {
        Ord::cmp(self.as_c_str(), other)
    }
}

#[derive(Debug)]
pub struct StringCache {
    values: Vec<CString>,
    indexes: Vec<usize>,
}

impl StringCache {
    #[inline]
    pub fn new() -> Self {
        Self {
            values: Vec::new(),
            indexes: Vec::new(),
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn get(&self, index: usize) -> Option<&CStr> {
        self.values.get(index).map(CString::as_c_str)
    }

    #[inline]
    pub unsafe fn get_unchecked(&self, index: usize) -> &CStr {
        unsafe { self.values.get_unchecked(index) }.as_c_str()
    }

    pub fn get_index<T: OrdCStr>(&self, string: T) -> Option<usize> {
        self.binary_search(&string)
            .ok()
            .map(|i| unsafe { *self.indexes.get_unchecked(i) })
    }

    pub fn insert<T: OrdCStr + Into<CString>>(&mut self, string: T) -> usize {
        match self.binary_search(&string) {
            Ok(i) => unsafe { *self.indexes.get_unchecked(i) },
            Err(i) => {
                let res = self.values.len();
                self.values.push(string.into());
                self.indexes.insert(i, res);
                res
            }
        }
    }

    pub fn binary_search<T: OrdCStr>(&self, search: T) -> Result<usize, usize> {
        self.indexes.binary_search_by(|&i| {
            search
                .cmp(unsafe { self.values.get_unchecked(i) })
                .reverse()
        })
    }

    pub fn shrink_to_fit(&mut self) {
        self.values.shrink_to_fit();
        self.indexes.shrink_to_fit();
    }
}

impl Default for StringCache {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
