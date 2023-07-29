#[allow(deprecated)]
use crate::{
    borrow::Borrow,
    cell::{Cell, OnceCell},
    fmt::{self, Debug},
    hash::{BuildHasher, Hash, Hasher, SipHasher},
    iter::FusedIterator,
    ops::Index,
    ops::{Deref, DerefMut},
    prelude::rust_2021::*,
};

#[derive(Clone)]
pub struct RandomState {
    k0: u64,
    k1: u64,
}

#[derive(Clone, Debug)]
#[allow(deprecated)]
pub struct DefaultHasher(SipHasher);

pub struct FakeSyncCell<T: ?Sized> {
    inner: T,
}

impl<T> FakeSyncCell<T> {
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    #[inline]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    #[inline]
    #[allow(clippy::cast_ref_to_mut)]
    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *(&self.inner as *const T as *mut T) }
    }
}

unsafe impl<T: ?Sized> Send for FakeSyncCell<T> {}
unsafe impl<T: ?Sized> Sync for FakeSyncCell<T> {}

impl<T> Deref for FakeSyncCell<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get_ref()
    }
}

impl<T> DerefMut for FakeSyncCell<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

fn hashmap_random_keys() -> (u64, u64) {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    fn fill_bytes(buf: &mut [u8]) {
        use crate::{
            ffi::CStr,
            io::{Errno, Read},
        };

        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn getrandom(buf: &mut [u8]) -> Result<usize, Errno> {
            use crate::sync::atomic::{AtomicBool, Ordering};
            use linux_syscalls::{syscall, Sysno};

            static GRND_INSECURE_AVAILABLE: AtomicBool = AtomicBool::new(true);
            if GRND_INSECURE_AVAILABLE.load(Ordering::Relaxed) {
                match unsafe {
                    syscall!(
                        Sysno::getrandom,
                        buf.as_mut_ptr(),
                        buf.len(),
                        linux_raw_sys::general::GRND_INSECURE
                    )
                } {
                    Err(Errno::EINVAL) | Err(Errno::ENOSYS) => {
                        GRND_INSECURE_AVAILABLE.store(false, Ordering::Relaxed);
                    }
                    Ok(len) => return Ok(len),
                    _ => (),
                }
            }

            unsafe {
                syscall!(
                    Sysno::getrandom,
                    buf.as_mut_ptr(),
                    buf.len(),
                    linux_raw_sys::general::GRND_NONBLOCK
                )
            }
        }

        #[cfg(target_os = "freebsd")]
        fn getrandom(buf: &mut [u8]) -> Result<usize, Errno> {
            extern "C" {
                fn getrandom(
                    buf: *mut libc::c_void,
                    length: libc::size_t,
                    flags: libc::c_uint,
                ) -> libc::ssize_t;
            }

            match unsafe { getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) } {
                -1 => Err(Errno::last_os_error()),
                len => Ok(len as usize),
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        fn getrandom_fill_bytes(v: &mut [u8]) -> bool {
            use crate::sync::atomic::{AtomicBool, Ordering};

            static GETRANDOM_UNAVAILABLE: AtomicBool = AtomicBool::new(false);
            if GETRANDOM_UNAVAILABLE.load(Ordering::Relaxed) {
                return false;
            }

            let mut read = 0;
            while read < v.len() {
                match getrandom(&mut v[read..]) {
                    Err(Errno::EINTR) => continue,
                    Err(Errno::ENOSYS) | Err(Errno::EPERM) => {
                        GETRANDOM_UNAVAILABLE.store(true, Ordering::Relaxed);
                        return false;
                    }
                    Err(err) => panic!("unexpected getrandom error: {}", err),
                    Ok(len) => {
                        read += len;
                    }
                }
            }
            true
        }

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        if getrandom_fill_bytes(buf) {
            return;
        }

        // TODO: implements fast random for apple, dragonfly, netbsd and openbsd

        let mut file = crate::fs::OpenOptions::new()
            .read(true)
            .open_cstr(unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/urandom\0") })
            .expect("failed to open /dev/urandom");
        file.read_exact(buf).expect("failed to read /dev/urandom");
    }

    const KEY_LEN: usize = crate::mem::size_of::<u64>();

    let mut v = [0u8; KEY_LEN * 2];
    fill_bytes(&mut v);
    let key1 = v[0..KEY_LEN].try_into().unwrap();
    let key2 = v[KEY_LEN..].try_into().unwrap();

    (u64::from_ne_bytes(key1), u64::from_ne_bytes(key2))
}

fn keys() -> &'static Cell<(u64, u64)> {
    static INSTANCE: FakeSyncCell<OnceCell<Cell<(u64, u64)>>> = FakeSyncCell::new(OnceCell::new());
    INSTANCE.get_or_init(|| Cell::new(hashmap_random_keys()))
}

impl DefaultHasher {
    #[inline]
    #[allow(deprecated)]
    #[must_use]
    pub fn new() -> Self {
        Self(SipHasher::new_with_keys(0, 0))
    }
}

impl Default for DefaultHasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for DefaultHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl RandomState {
    #[must_use]
    pub fn new() -> Self {
        let keys = keys();
        let (k0, k1) = keys.get();
        keys.set((k0.wrapping_add(1), k1));
        Self { k0, k1 }
    }
}

impl Default for RandomState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for RandomState {
    type Hasher = DefaultHasher;

    #[inline]
    #[allow(deprecated)]
    fn build_hasher(&self) -> Self::Hasher {
        DefaultHasher(SipHasher::new_with_keys(self.k0, self.k1))
    }
}

impl fmt::Debug for RandomState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandomState").finish_non_exhaustive()
    }
}

pub struct HashMap<K, V, S = RandomState> {
    base: hashbrown::HashMap<K, V, S>,
}

impl<K, V> HashMap<K, V, RandomState> {
    #[inline]
    #[must_use]
    pub fn new() -> HashMap<K, V, RandomState> {
        Default::default()
    }

    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        HashMap::with_capacity_and_hasher(capacity, Default::default())
    }
}

impl<K, V, S> HashMap<K, V, S> {
    #[inline]
    pub fn with_hasher(hash_builder: S) -> Self {
        Self {
            base: hashbrown::HashMap::with_hasher(hash_builder),
        }
    }

    #[inline]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: S) -> Self {
        Self {
            base: hashbrown::HashMap::with_capacity_and_hasher(capacity, hash_builder),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.base.capacity()
    }

    #[inline]
    pub fn keys(&self) -> Keys<'_, K, V> {
        Keys { inner: self.iter() }
    }

    #[inline]
    pub fn into_keys(self) -> IntoKeys<K, V> {
        IntoKeys {
            inner: self.into_iter(),
        }
    }

    #[inline]
    pub fn values(&self) -> Values<'_, K, V> {
        Values { inner: self.iter() }
    }

    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        ValuesMut {
            inner: self.iter_mut(),
        }
    }

    #[inline]
    pub fn into_values(self) -> IntoValues<K, V> {
        IntoValues {
            inner: self.into_iter(),
        }
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            base: self.base.iter(),
        }
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut {
            base: self.base.iter_mut(),
        }
    }

    #[inline]
    pub fn drain(&mut self) -> Drain<'_, K, V> {
        Drain {
            base: self.base.drain(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.base.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
    }

    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.base.retain(f)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.base.clear();
    }

    #[inline]
    pub fn hasher(&self) -> &S {
        self.base.hasher()
    }
}

impl<K, V, S> HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.base.reserve(additional)
    }

    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.base.shrink_to_fit();
    }

    #[inline]
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.base.shrink_to(min_capacity);
    }

    // #[inline]
    // pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
    //     map_entry(self.base.rustc_entry(key))
    // }

    #[inline]
    pub fn get<Q: ?Sized>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.base.get(k)
    }

    #[inline]
    pub fn get_key_value<Q: ?Sized>(&self, k: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.base.get_key_value(k)
    }

    #[inline]
    pub fn contains_key<Q: ?Sized>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.base.contains_key(k)
    }

    #[inline]
    pub fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.base.get_mut(k)
    }

    #[inline]
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.base.insert(k, v)
    }

    #[inline]
    pub fn remove<Q: ?Sized>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.base.remove(k)
    }

    #[inline]
    pub fn remove_entry<Q: ?Sized>(&mut self, k: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        self.base.remove_entry(k)
    }
}

impl<K, V, S> Clone for HashMap<K, V, S>
where
    K: Clone,
    V: Clone,
    S: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
        }
    }

    #[inline]
    fn clone_from(&mut self, other: &Self) {
        self.base.clone_from(&other.base);
    }
}

impl<K, V, S> PartialEq for HashMap<K, V, S>
where
    K: Eq + Hash,
    V: PartialEq,
    S: BuildHasher,
{
    fn eq(&self, other: &HashMap<K, V, S>) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter()
            .all(|(key, value)| other.get(key).map_or(false, |v| *value == *v))
    }
}

impl<K, V, S> Eq for HashMap<K, V, S>
where
    K: Eq + Hash,
    V: Eq,
    S: BuildHasher,
{
}

impl<K, V, S> Default for HashMap<K, V, S>
where
    S: Default,
{
    #[inline]
    fn default() -> Self {
        Self::with_hasher(Default::default())
    }
}

impl<K, Q: ?Sized, V, S> Index<&Q> for HashMap<K, V, S>
where
    K: Eq + Hash + Borrow<Q>,
    Q: Eq + Hash,
    S: BuildHasher,
{
    type Output = V;

    #[inline]
    fn index(&self, key: &Q) -> &Self::Output {
        self.get(key).expect("no entry found for key")
    }
}

pub struct Iter<'a, K: 'a, V: 'a> {
    base: hashbrown::hash_map::Iter<'a, K, V>,
}

impl<K, V> Clone for Iter<'_, K, V> {
    #[inline]
    fn clone(&self) -> Self {
        Iter {
            base: self.base.clone(),
        }
    }
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    #[inline]
    fn next(&mut self) -> Option<(&'a K, &'a V)> {
        self.base.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.base.size_hint()
    }
}

impl<K, V> ExactSizeIterator for Iter<'_, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<K, V> FusedIterator for Iter<'_, K, V> {}

impl<K: Debug, V: Debug> fmt::Debug for Iter<'_, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.clone()).finish()
    }
}

impl<'a, K, V, S> IntoIterator for &'a HashMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct IterMut<'a, K: 'a, V: 'a> {
    base: hashbrown::hash_map::IterMut<'a, K, V>,
}

impl<'a, K: 'a, V: 'a> IterMut<'a, K, V> {
    #[inline]
    pub(super) fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            base: self.base.rustc_iter(),
        }
    }
}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    #[inline]
    fn next(&mut self) -> Option<(&'a K, &'a mut V)> {
        self.base.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.base.size_hint()
    }
}

impl<K, V> ExactSizeIterator for IterMut<'_, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<K, V> FusedIterator for IterMut<'_, K, V> {}

impl<K: Debug, V: Debug> fmt::Debug for IterMut<'_, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<'a, K, V, S> IntoIterator for &'a mut HashMap<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

pub struct IntoIter<K, V> {
    base: hashbrown::hash_map::IntoIter<K, V>,
}

impl<K, V> IntoIter<K, V> {
    #[inline]
    pub(super) fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            base: self.base.rustc_iter(),
        }
    }
}

impl<K, V> Iterator for IntoIter<K, V> {
    type Item = (K, V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.base.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.base.size_hint()
    }
}

impl<K, V> ExactSizeIterator for IntoIter<K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<K, V> FusedIterator for IntoIter<K, V> {}

impl<K: Debug, V: Debug> fmt::Debug for IntoIter<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V, S> IntoIterator for HashMap<K, V, S> {
    type Item = (K, V);

    type IntoIter = IntoIter<K, V>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            base: self.base.into_iter(),
        }
    }
}

pub struct Keys<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Keys<'a, K, V> {
    type Item = &'a K;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, _)| k)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, K, V> ExactSizeIterator for Keys<'a, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a, K, V> FusedIterator for Keys<'a, K, V> {}

impl<'a, K, V> Clone for Keys<'a, K, V> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<'a, K: Debug, V: Debug> fmt::Debug for Keys<'a, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

pub struct Values<'a, K, V> {
    inner: Iter<'a, K, V>,
}

impl<'a, K, V> Iterator for Values<'a, K, V> {
    type Item = &'a V;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, K, V> ExactSizeIterator for Values<'a, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a, K, V> FusedIterator for Values<'a, K, V> {}

impl<'a, K, V> Clone for Values<'a, K, V> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<'a, K: Debug, V: Debug> fmt::Debug for Values<'a, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

pub struct ValuesMut<'a, K, V> {
    inner: IterMut<'a, K, V>,
}

impl<'a, K, V> Iterator for ValuesMut<'a, K, V> {
    type Item = &'a mut V;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a, K, V> ExactSizeIterator for ValuesMut<'a, K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a, K, V> FusedIterator for ValuesMut<'a, K, V> {}

impl<'a, K: Debug, V: Debug> fmt::Debug for ValuesMut<'a, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.inner.iter().map(|(_, v)| v))
            .finish()
    }
}

pub struct IntoKeys<K, V> {
    inner: IntoIter<K, V>,
}

impl<K, V> Iterator for IntoKeys<K, V> {
    type Item = K;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, _)| k)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V> ExactSizeIterator for IntoKeys<K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<K, V> FusedIterator for IntoKeys<K, V> {}

impl<K: Debug, V: Debug> fmt::Debug for IntoKeys<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.inner.iter().map(|(k, _)| k))
            .finish()
    }
}

pub struct IntoValues<K, V> {
    inner: IntoIter<K, V>,
}

impl<K, V> Iterator for IntoValues<K, V> {
    type Item = V;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V> ExactSizeIterator for IntoValues<K, V> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<K, V> FusedIterator for IntoValues<K, V> {}

impl<K: Debug, V: Debug> fmt::Debug for IntoValues<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.inner.iter().map(|(_, v)| v))
            .finish()
    }
}

pub struct Drain<'a, K, V> {
    base: hashbrown::hash_map::Drain<'a, K, V>,
}

impl<'a, K, V> Drain<'a, K, V> {
    pub(super) fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            base: self.base.rustc_iter(),
        }
    }
}

impl<'a, K, V> Iterator for Drain<'a, K, V> {
    type Item = (K, V);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.base.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.base.size_hint()
    }
}

impl<'a, K, V> ExactSizeIterator for Drain<'a, K, V> {
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<'a, K, V> FusedIterator for Drain<'a, K, V> {}

impl<'a, K: Debug, V: Debug> fmt::Debug for Drain<'a, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K, V, const N: usize> From<[(K, V); N]> for HashMap<K, V, RandomState>
where
    K: Eq + Hash,
{
    #[inline]
    fn from(arr: [(K, V); N]) -> Self {
        Self::from_iter(arr)
    }
}

impl<K, V, S> FromIterator<(K, V)> for HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut map = HashMap::with_hasher(Default::default());
        map.extend(iter);
        map
    }
}

impl<K, V, S> Extend<(K, V)> for HashMap<K, V, S>
where
    K: Eq + Hash,
    S: BuildHasher + Default,
{
    #[inline]
    fn extend<T: IntoIterator<Item = (K, V)>>(&mut self, iter: T) {
        self.base.extend(iter)
    }
}

impl<'a, K, V, S> Extend<(&'a K, &'a V)> for HashMap<K, V, S>
where
    K: Eq + Hash + Copy,
    V: Copy,
    S: BuildHasher,
{
    #[inline]
    fn extend<T: IntoIterator<Item = (&'a K, &'a V)>>(&mut self, iter: T) {
        self.base.extend(iter)
    }
}
