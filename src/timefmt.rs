//! Small time and size formatting helpers (UTC only, no time-zone database needed).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, now.
pub fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Formats Unix seconds as an RFC 3339 UTC timestamp, e.g. `2026-11-19T12:34:56Z`.
pub fn rfc3339_utc(unix_secs: i64) -> String {
    let t = utc_parts(unix_secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

/// A UTC calendar date and time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtcParts {
    pub year: i64,
    /// 1 to 12
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
}

/// Breaks Unix seconds into a UTC date and time.
pub fn utc_parts(unix_secs: i64) -> UtcParts {
    let (year, month, day) = civil_from_days(unix_secs.div_euclid(86_400));
    let second_of_day = unix_secs.rem_euclid(86_400);
    UtcParts {
        year,
        month,
        day,
        hour: second_of_day / 3600,
        minute: second_of_day % 3600 / 60,
        second: second_of_day % 60,
    }
}

// AIDEV-NOTE: civil_from_days / days_from_civil are Howard Hinnant's public-domain
// proleptic Gregorian calendar algorithms; the tests pin them to known dates.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// Parses a `YYYY-MM-DD` date to Unix seconds at 00:00 UTC. Returns `None` for anything
/// that is not a real calendar date.
pub fn parse_date(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400)
}

/// Formats a byte count with binary units, e.g. `1.5 KiB`.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

/// Formats a duration in seconds compactly, e.g. `1d 1h 1m`.
pub fn human_duration(secs: u64) -> String {
    let (days, hours, minutes, seconds) = (
        secs / 86_400,
        secs % 86_400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_utc_formats_known_instants() {
        let cases: &[(i64, &str)] = &[
            (0, "1970-01-01T00:00:00Z"),
            (-1, "1969-12-31T23:59:59Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_795_091_696, "2026-11-19T12:34:56Z"),
            (4_102_444_799, "2099-12-31T23:59:59Z"),
        ];
        for (secs, want) in cases {
            assert_eq!(rfc3339_utc(*secs), *want, "secs {secs}");
        }
    }

    #[test]
    fn utc_parts_breaks_an_instant_into_date_and_time() {
        let want = UtcParts {
            year: 2026,
            month: 11,
            day: 19,
            hour: 12,
            minute: 34,
            second: 56,
        };
        assert_eq!(utc_parts(1_795_091_696), want);
    }

    #[test]
    fn parse_date_accepts_only_real_dates() {
        let cases: &[(&str, Option<i64>)] = &[
            ("1970-01-01", Some(0)),
            ("2000-02-29", Some(951_782_400)),
            ("2026-11-19", Some(1_795_046_400)),
            ("2025-02-29", None),
            ("2026-02-30", None),
            ("2026-13-01", None),
            ("2026-00-10", None),
            ("2026-1-1", None),
            ("2026-11-19T00:00:00Z", None),
            ("garbage", None),
            ("", None),
        ];
        for (text, want) in cases {
            assert_eq!(parse_date(text), *want, "text {text:?}");
        }
    }

    #[test]
    fn human_bytes_uses_binary_units() {
        let cases: &[(u64, &str)] = &[
            (0, "0 B"),
            (1023, "1023 B"),
            (1024, "1.0 KiB"),
            (1536, "1.5 KiB"),
            (1_073_741_824, "1.0 GiB"),
            (u64::MAX, "16.0 EiB"),
        ];
        for (n, want) in cases {
            assert_eq!(human_bytes(*n), *want, "bytes {n}");
        }
    }

    #[test]
    fn human_duration_drops_units_that_do_not_matter() {
        let cases: &[(u64, &str)] = &[
            (0, "0s"),
            (59, "59s"),
            (60, "1m 0s"),
            (3661, "1h 1m"),
            (90_061, "1d 1h 1m"),
        ];
        for (secs, want) in cases {
            assert_eq!(human_duration(*secs), *want, "secs {secs}");
        }
    }
}
