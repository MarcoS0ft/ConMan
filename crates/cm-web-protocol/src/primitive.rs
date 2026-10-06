use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecimalI64(pub i64);

impl Serialize for DecimalI64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DecimalI64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value == "-0"
            || value.starts_with('+')
            || (value.len() > 1 && value.starts_with('0'))
            || (value.starts_with('-') && value.as_bytes().get(1) == Some(&b'0'))
            || !value
                .strip_prefix('-')
                .unwrap_or(&value)
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        {
            return Err(de::Error::custom("non-canonical signed decimal"));
        }
        value
            .parse::<i64>()
            .map(Self)
            .map_err(|_| de::Error::custom("signed decimal out of range"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecimalU64(pub u64);

impl Serialize for DecimalU64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.starts_with('+')
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(de::Error::custom("non-canonical unsigned decimal"));
        }
        value
            .parse::<u64>()
            .map(Self)
            .map_err(|_| de::Error::custom("unsigned decimal out of range"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalUuid(pub Uuid);

impl Serialize for CanonicalUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

impl<'de> Deserialize<'de> for CanonicalUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let parsed = Uuid::from_str(&value).map_err(|_| de::Error::custom("invalid UUID"))?;
        if parsed.hyphenated().to_string() != value {
            return Err(de::Error::custom("non-canonical UUID spelling"));
        }
        Ok(Self(parsed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Sha256Hex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(de::Error::custom("invalid lowercase SHA-256 hex"));
        }
        Ok(Self(value))
    }
}

pub type BuildId = Sha256Hex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RequiredNullable<T>(pub Option<T>);

pub fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> Result<RequiredNullable<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct RequiredNullableVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for RequiredNullableVisitor<T> {
        type Value = RequiredNullable<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a present nullable value")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(RequiredNullable(None))
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(RequiredNullable(None))
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            T::deserialize(deserializer).map(|value| RequiredNullable(Some(value)))
        }
    }

    deserializer.deserialize_option(RequiredNullableVisitor(std::marker::PhantomData))
}
