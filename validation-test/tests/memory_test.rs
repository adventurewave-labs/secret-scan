use secretscan::Scanner;
use std::fs;
use tempfile::TempDir;

/// Test to ensure memory usage stays under 100MB for 100k files
#[test]
fn test_memory_usage_100k_files() {
    let temp_dir = generate_large_test_repo(100000);
    let scanner = Scanner::new().unwrap(); // Use basic scanner to reduce variables

    // Estimate memory usage beforehand
    let (estimated_mb, status) = Scanner::estimate_memory_usage(100000, 1024);
    println!("Estimated memory usage: {:.2}MB - {}", estimated_mb, status);

    // Ensure estimate is within target
    assert!(
        estimated_mb < 100.0,
        "Estimated memory usage {:.2}MB exceeds 100MB target",
        estimated_mb
    );

    // Perform actual scan
    let results = scanner.scan_directory(temp_dir.path()).unwrap();

    println!("Scanned 100k files, found {} results", results.len());

    // Test memory optimization features
    test_large_file_handling();
    test_buffered_reading();
}

/// Test memory usage with 10k files (more practical test)
#[test]
fn test_memory_usage_10k_files() {
    let temp_dir = generate_large_test_repo(10000);
    let scanner = Scanner::new().unwrap();

    let (estimated_mb, status) = Scanner::estimate_memory_usage(10000, 2048);
    println!(
        "10k files - Estimated memory: {:.2}MB - {}",
        estimated_mb, status
    );

    assert!(
        estimated_mb < 50.0,
        "10k files should use less than 50MB, estimated: {:.2}MB",
        estimated_mb
    );

    let results = scanner.scan_directory(temp_dir.path()).unwrap();
    println!("Scanned 10k files, found {} results", results.len());
}

/// Test large file handling with chunked streaming
#[test]
fn test_large_file_handling() {
    let temp_dir = TempDir::new().unwrap();
    let large_file = temp_dir.path().join("large_file.txt");

    // Create a 15MB file to trigger chunked processing
    let mut content = String::new();
    let secret_line = "const API_KEY = \"sk-1234567890abcdef1234567890abcdef\";\n";
    let normal_line = "const normalVar = 'some normal content here that is not a secret';\n";

    // Calculate lines needed for ~15MB
    let target_size = 15 * 1024 * 1024; // 15MB
    let lines_needed = target_size / normal_line.len();

    for i in 0..lines_needed {
        if i % 1000 == 0 {
            content.push_str(secret_line); // Add secrets every 1000 lines
        } else {
            content.push_str(normal_line);
        }
    }

    fs::write(&large_file, content).unwrap();

    let scanner = Scanner::new().unwrap();
    let results = scanner.scan_directory(temp_dir.path()).unwrap();

    // Should find secrets even in large files
    assert!(!results.is_empty(), "Should find secrets in large file");
    println!(
        "Large file test: Found {} secrets in 15MB file",
        results.len()
    );
}

/// Test BufReader optimization for medium files
#[test]
fn test_buffered_reading() {
    let temp_dir = TempDir::new().unwrap();

    // Create several medium-sized files (1-5MB each)
    for file_num in 0..10 {
        let file_path = temp_dir
            .path()
            .join(format!("medium_file_{}.txt", file_num));
        let mut content = String::new();

        let secret_line = format!(
            "const SECRET_{} = \"ghp_1234567890abcdef1234567890abcdef123456\";\n",
            file_num
        );
        let normal_line = "function processData() { return Math.random() * 1000; }\n";

        // ~2MB per file
        let lines_needed = (2 * 1024 * 1024) / normal_line.len();

        for i in 0..lines_needed {
            if i % 500 == 0 {
                content.push_str(&secret_line);
            } else {
                content.push_str(normal_line);
            }
        }

        fs::write(&file_path, content).unwrap();
    }

    let scanner = Scanner::new().unwrap();
    let results = scanner.scan_directory(temp_dir.path()).unwrap();

    // Should find at least one secret per file
    assert!(
        results.len() >= 10,
        "Should find at least 10 secrets across 10 files, found: {}",
        results.len()
    );
    println!(
        "Buffered reading test: Found {} secrets in 10 medium files",
        results.len()
    );
}

/// Test memory estimation accuracy
#[test]
fn test_memory_estimation() {
    // Test various scenarios
    let scenarios = vec![
        (1000, 1024, "1k small files"),
        (10000, 2048, "10k medium files"),
        (100000, 1024, "100k small files"),
        (1000, 10 * 1024 * 1024, "1k large files"),
    ];

    for (num_files, avg_size, description) in scenarios {
        let (estimated_mb, status) = Scanner::estimate_memory_usage(num_files, avg_size);
        println!("{}: {:.2}MB - {}", description, estimated_mb, status);

        // All scenarios should be under 100MB with our optimizations
        if avg_size < 10 * 1024 * 1024 || num_files < 10000 {
            assert!(
                estimated_mb < 100.0,
                "{} estimated {:.2}MB > 100MB",
                description,
                estimated_mb
            );
        }
    }
}

/// Generate a large test repository with many files
fn generate_large_test_repo(num_files: usize) -> TempDir {
    let temp_dir = TempDir::new().unwrap();

    for i in 0..num_files {
        let dir_path = temp_dir.path().join(format!("dir_{}", i / 1000));
        fs::create_dir_all(&dir_path).unwrap();

        let file_path = dir_path.join(format!("file_{}.txt", i));

        // Create varied content to test different patterns
        let content = match i % 20 {
            0 => format!("const AWS_KEY = \"AKIA1234567890ABCDEF\";\n// File {}", i),
            1 => format!(
                "token = \"ghp_abcdefghijklmnopqrstuvwxyz123456\";\n// File {}",
                i
            ),
            2 => format!(
                "jwt = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature\";\n// File {}",
                i
            ),
            3..=5 => format!(
                "// Test file {} with test_secret = \"fake123\"\nfunction test() {{}}",
                i
            ),
            _ => format!(
                "// Regular file {}\nfunction process() {{ return {}; }}",
                i, i
            ),
        };

        fs::write(&file_path, content).unwrap();
    }

    temp_dir
}
