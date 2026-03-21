use kernriftc::SurfaceProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LivingCompilerFormat {
    Text,
    Json,
}

impl LivingCompilerFormat {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "invalid living-compiler mode: unsupported --format '{}' (expected 'text' or 'json')",
                other
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LivingCompilerArgs {
    pub(crate) input_path: String,
    pub(crate) surface: SurfaceProfile,
    pub(crate) format: LivingCompilerFormat,
}

pub(crate) fn parse_living_compiler_args(args: &[String]) -> Result<LivingCompilerArgs, String> {
    let mut surface = SurfaceProfile::Stable;
    let mut format = LivingCompilerFormat::Text;
    let mut positionals: Vec<String> = Vec::new();

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--surface" => {
                let Some(value) = args.get(idx + 1) else {
                    return Err(
                        "invalid living-compiler mode: --surface requires a value".to_string()
                    );
                };
                surface = SurfaceProfile::parse(value)
                    .map_err(|err| format!("invalid living-compiler mode: {}", err))?;
                idx += 2;
            }
            "--format" => {
                let Some(value) = args.get(idx + 1) else {
                    return Err(
                        "invalid living-compiler mode: --format requires a value".to_string()
                    );
                };
                format = LivingCompilerFormat::parse(value)?;
                idx += 2;
            }
            other if other.starts_with('-') => {
                return Err(format!(
                    "invalid living-compiler mode: unknown flag '{}'",
                    other
                ));
            }
            other => {
                positionals.push(other.to_string());
                idx += 1;
            }
        }
    }

    if positionals.len() != 1 {
        return Err(
            "invalid living-compiler mode: expected exactly one <file.kr> input".to_string(),
        );
    }

    Ok(LivingCompilerArgs {
        input_path: positionals.pop().expect("exactly one positional"),
        surface,
        format,
    })
}
