//! Simple utility to embedded parameters in binary
//! Prevent issue with runtime path
//! Enable name-based selection in CLI
//!

use tfhe::tfhe_hpu_backend::prelude::*;

/// Simple enum used to build hpu params by name
/// User should provide a predefined name or a custom string-path
#[derive(Debug, Clone)]
pub enum ParamsName {
    // 44b gaussian
    Gaussian44bFast,
    Gaussian44b,

    // 64b gaussian
    Gaussian64bFast,
    Gaussian64b,
    Gaussian64bPFail64,
    Gaussian64bPFail64Psi64,

    // 64b TUniform
    TUniform64bFast,
    TUniform64bPFail64Psi64,
    TUniform64bPFail128Psi64,

    // Custom
    CustomPath(ShellString),
}

impl std::str::FromStr for ParamsName {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "gaussian44bfast" | "gaussian-44b-fast" => Self::Gaussian44bFast,
            "gaussian44b" | "gaussian-44b" => Self::Gaussian44b,
            "gaussian64bfast" | "gaussian-64b-fast" => Self::Gaussian64bFast,
            "gaussian64b" | "gaussian-64b" => Self::Gaussian64b,
            "gaussian64bpfail64" | "gaussian-64b-pfail64" => Self::Gaussian64bPFail64,
            "gaussian64bpfail64psi64" | "gaussian-64b-pfail64-psi64" => {
                Self::Gaussian64bPFail64Psi64
            }
            "tuniform64bfast" | "tuniform-64b-fast" => Self::TUniform64bFast,
            "tuniform64bpfail64psi64" | "tuniform-64b-pfail64-psi64" => {
                Self::TUniform64bPFail64Psi64
            }
            "tuniform64bpfail128psi64" | "tuniform-64b-pfail128-psi64" => {
                Self::TUniform64bPFail128Psi64
            }
            other => Self::CustomPath(ShellString::new(other.to_string())),
        })
    }
}

impl From<&ParamsName> for HpuParameters {
    fn from(name: &ParamsName) -> Self {
        fn from_raw_string(name: &ParamsName, toml_str: &str) -> HpuParameters {
            match toml::from_str(&toml_str) {
                Ok(cfg) => cfg,
                Err(err) => panic!("Error in toml_str {name:?}: {err}"),
            }
        }
        match name {
            ParamsName::Gaussian44bFast => {
                let toml_str = include_str!("gaussian_44b_fast.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::Gaussian44b => {
                let toml_str = include_str!("gaussian_44b.toml");
                from_raw_string(name, toml_str)
            }

            ParamsName::Gaussian64bFast => {
                let toml_str = include_str!("gaussian_64b_fast.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::Gaussian64b => {
                let toml_str = include_str!("gaussian_64b.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::Gaussian64bPFail64 => {
                let toml_str = include_str!("gaussian_64b_pfail64.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::Gaussian64bPFail64Psi64 => {
                let toml_str = include_str!("gaussian_64b_pfail64_psi64.toml");
                from_raw_string(name, toml_str)
            }

            ParamsName::TUniform64bFast => {
                let toml_str = include_str!("tuniform_64b_fast.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::TUniform64bPFail64Psi64 => {
                let toml_str = include_str!("tuniform_64b_pfail64_psi64.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::TUniform64bPFail128Psi64 => {
                let toml_str = include_str!("tuniform_64b_pfail128_psi64.toml");
                from_raw_string(name, toml_str)
            }
            ParamsName::CustomPath(path) => {
                let expand_path = path.expand();
                HpuParameters::from_toml(&expand_path)
            }
        }
    }
}
