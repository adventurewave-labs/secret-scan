pub mod baseline;
pub mod config;
pub mod context;
pub mod entropy;
pub mod git;
pub mod output;
pub mod patterns;
pub mod placeholder;
pub mod scanner;
pub mod validate;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub file_path: PathBuf,
    pub line_number: usize,
    pub line_content: String,
    pub pattern_name: String,
    pub matched_text: String,
    pub entropy: Option<f64>,
}

pub use context::*;
pub use entropy::*;
pub use output::*;
pub use patterns::*;
pub use scanner::Scanner;
