// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub fn split_nth_slash(url: &str, n: usize) -> Option<(&str, &str)> {
    let mut split_pos = None;
    let mut splits = url.match_indices('/');

    for _ in 0..n {
        split_pos = splits.next();
    }

    split_pos.map(|(idx, pat)| url.split_at(idx + pat.len() - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_nth_slash() {
        let url_path = "/cdh/resource/default/";
        assert_eq!(split_nth_slash(url_path, 0), None);
        assert_eq!(
            split_nth_slash(url_path, 1),
            Some(("", "/cdh/resource/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 2),
            Some(("/cdh", "/resource/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 3),
            Some(("/cdh/resource", "/default/"))
        );
        assert_eq!(
            split_nth_slash(url_path, 4),
            Some(("/cdh/resource/default", "/"))
        );
        assert_eq!(split_nth_slash(url_path, 5), None);
    }
}
