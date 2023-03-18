pub struct GroupEntry<'a> {
    pub name: &'a [u8],
    pub password: Option<&'a [u8]>,
    pub gid: u32,
    pub users: Option<UserList<'a>>,
}

pub struct UserList<'a> {
    buf: Option<&'a [u8]>,
}

impl<'a> UserList<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf: Some(buf) }
    }
}

impl<'a> Iterator for UserList<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.buf.take()?;

        match memchr::memchr(b',', buf) {
            Some(i) => {
                let res = &buf[..i];
                self.buf = buf.get((i + 1)..);
                Some(res)
            }
            None => Some(buf),
        }
    }
}

fn parse_line(line: &[u8]) -> Option<GroupEntry> {
    fn next_field(offset: usize, line: &[u8]) -> Option<(&[u8], usize)> {
        let i = memchr::memchr(b':', &line[offset..])? + offset;
        Some((unsafe { line.get_unchecked(offset..i) }, i + 1))
    }
    fn next_field_u32(offset: usize, line: &[u8]) -> Option<(u32, usize)> {
        let (field, offset) = next_field(offset, line)?;
        Some((atoi::atoi(field)?, offset))
    }

    let (name, offset) = next_field(0, line)?;
    let (password, offset) = {
        let (field, offset) = next_field(offset, line)?;

        if field.len() == 1 && unsafe { *field.get_unchecked(0) } == b'x' {
            (None, offset)
        } else {
            (Some(field), offset)
        }
    };
    let (gid, offset) = next_field_u32(offset, line)?;
    let users = if line.get(offset..).map(|x| x.is_empty()).unwrap_or(true) {
        None
    } else {
        Some(UserList::new(unsafe { line.get_unchecked(offset..) }))
    };

    Some(GroupEntry {
        name,
        password,
        gid,
        users,
    })
}

pub fn parse_content(content: &[u8]) -> impl Iterator<Item = Option<GroupEntry>> {
    super::Lines::new(content).map(parse_line)
}
