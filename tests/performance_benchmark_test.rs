use secretscan::Scanner;
use std::fs;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn test_scanning_performance_small_files() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create 100 small files with secrets
    for i in 0..100 {
        let content = format!(
            r#"// File {}
const CONFIG = {{
    api_key: "AKIA{}",
    github_token: "ghp_{}",
    secret: "{}",
}};
"#,
            i,
            format!("{:016}", i), // 16 chars after AKIA
            format!("{:036}", i), // 36 chars after ghp_
            format!("secret_value_{:08}", i)
        );
        fs::write(temp_path.join(format!("file_{}.js", i)), content).unwrap();
    }
    
    let scanner = Scanner::new().unwrap();
    
    // Measure scan time
    let start = Instant::now();
    let findings = scanner.scan_directory(temp_path).unwrap();
    let duration = start.elapsed();
    
    println!("Small files performance:");
    println!("  Files: 100");
    println!("  Findings: {}", findings.len());
    println!("  Time: {:?}", duration);
    println!("  Files/sec: {:.2}", 100.0 / duration.as_secs_f64());
    
    // Should find secrets in all files
    assert!(findings.len() >= 200, "Should find at least 200 secrets"); // 2 per file minimum
    
    // Should be fast (under 2 seconds for 100 small files)
    assert!(
        duration < Duration::from_secs(2),
        "Scanning 100 small files should take less than 2 seconds, took {:?}",
        duration
    );
}

#[test]
fn test_scanning_performance_large_files() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create 10 large files (each ~100KB) with secrets scattered throughout
    for i in 0..10 {
        let mut content = String::new();
        
        // Add lots of normal content
        for line in 0..2000 {
            content.push_str(&format!("// Line {} in file {}\n", line, i));
            content.push_str(&format!("let variable_{} = \"normal_value_{}\";\n", line, line));
            
            // Scatter secrets throughout
            if line % 200 == 0 {
                content.push_str(&format!("let secret_{} = \"AKIA{:016}\";\n", line, i * 1000 + line));
            }
            if line % 300 == 0 {
                content.push_str(&format!("const token_{} = \"ghp_{:036}\";\n", line, i * 1000 + line));
            }
        }
        
        fs::write(temp_path.join(format!("large_file_{}.js", i)), content).unwrap();
    }
    
    let scanner = Scanner::new().unwrap();
    
    // Measure scan time
    let start = Instant::now();
    let findings = scanner.scan_directory(temp_path).unwrap();
    let duration = start.elapsed();
    
    println!("Large files performance:");
    println!("  Files: 10 (~100KB each)");
    println!("  Findings: {}", findings.len());
    println!("  Time: {:?}", duration);
    println!("  MB/sec: {:.2}", 1.0 / duration.as_secs_f64()); // ~1MB total
    
    // Should find secrets (10-20 per file)
    assert!(findings.len() >= 100, "Should find at least 100 secrets in large files");
    
    // Should handle large files efficiently (under 5 seconds)
    assert!(
        duration < Duration::from_secs(5),
        "Scanning 10 large files should take less than 5 seconds, took {:?}",
        duration
    );
}

#[test]
fn test_scanning_performance_many_patterns() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create file with many different types of secrets to test all patterns
    let content = r#"
// AWS secrets
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// GitHub secrets
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const GITHUB_OAUTH = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

// Google secrets
const GOOGLE_API_KEY = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";
const GOOGLE_OAUTH = "123456789-abcdefghijklmnopqrstuvwx.apps.googleusercontent.com";

// JWT tokens
const JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Private keys
const RSA_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
const EC_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEII...\n-----END EC PRIVATE KEY-----";

// Database URLs
const POSTGRES_URL = "postgres://user:password@localhost:5432/db";
const MYSQL_URL = "mysql://root:secret@localhost:3306/app";
const MONGODB_URL = "mongodb://user:pass@localhost:27017/db";

// API keys
const OPENAI_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456";
const STRIPE_KEY = "sk_test_1234567890abcdefghijklmnop";
const SENDGRID_KEY = "SG.1234567890abcdefghijkl.1234567890abcdefghijkl";
const SLACK_TOKEN = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx";

// Azure secrets
const AZURE_TENANT = "12345678-1234-1234-1234-123456789012";
const AZURE_SECRET = "azure_client_secret = abcdefghijklmnopqrstuvwxyz123456789";

// PayPal secrets
const PAYPAL_CLIENT_ID = "paypal_client_id = AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz123456789";
const PAYPAL_SECRET = "paypal_secret = AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz123456789";

// Password patterns
const JSON_PASSWORD = '{"password": "my_secure_password_123"}';
const YAML_PASSWORD = "password: my_yaml_password_456";
const ENV_PASSWORD = "PASSWORD=my_env_password_789";

// Obfuscated secrets
const BASE64_SECRET = "api_key_b64 = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw";
const HEX_SECRET = "api_key_hex = 6162636465666768696a6b6c6d6e6f707172737475767778797a31323334353637383930";

// More API services
const DIGITALOCEAN_TOKEN = "dop_v1_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const DISCORD_TOKEN = "NzkyNzE1NDk0NzYxNjI4MTk2.X-hvzA.Ovy4MCQywSkoMRRclStW4xAYK7I";
const SHOPIFY_TOKEN = "shppa_12345678901234567890123456789012";
const GITLAB_TOKEN = "glpat-12345678901234567890";
"#;
    
    fs::write(temp_path.join("all_patterns.js"), content).unwrap();
    
    let scanner = Scanner::new().unwrap();
    
    // Measure scan time with many patterns
    let start = Instant::now();
    let findings = scanner.scan_directory(temp_path).unwrap();
    let duration = start.elapsed();
    
    println!("Many patterns performance:");
    println!("  Patterns tested: ~30 different types");
    println!("  Findings: {}", findings.len());
    println!("  Time: {:?}", duration);
    println!("  Patterns/sec: {:.2}", findings.len() as f64 / duration.as_secs_f64());
    
    // Should find most/all of the secrets
    assert!(findings.len() >= 25, "Should find at least 25 different secrets");
    
    // Should be efficient even with many patterns (under 1 second)
    assert!(
        duration < Duration::from_secs(1),
        "Testing many patterns should take less than 1 second, took {:?}",
        duration
    );
}

#[test]
fn test_scanning_performance_deep_directory() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create deep directory structure (5 levels deep, 5 directories per level)
    let mut total_files = 0;
    for level1 in 0..5 {
        for level2 in 0..5 {
            for level3 in 0..3 {
                let dir_path = temp_path.join(format!("level1_{}/level2_{}/level3_{}", level1, level2, level3));
                fs::create_dir_all(&dir_path).unwrap();
                
                // Add a few files at each level
                for file_num in 0..3 {
                    let content = format!(
                        r#"// Deep file {}-{}-{}-{}
const SECRET = "AKIA{:016}";
const TOKEN = "ghp_{:036}";
"#,
                        level1, level2, level3, file_num,
                        (level1 * 1000 + level2 * 100 + level3 * 10 + file_num),
                        (level1 * 1000 + level2 * 100 + level3 * 10 + file_num)
                    );
                    fs::write(dir_path.join(format!("file_{}.js", file_num)), content).unwrap();
                    total_files += 1;
                }
            }
        }
    }
    
    let scanner = Scanner::new().unwrap();
    
    // Measure scan time for deep directory
    let start = Instant::now();
    let findings = scanner.scan_directory(temp_path).unwrap();
    let duration = start.elapsed();
    
    println!("Deep directory performance:");
    println!("  Directory depth: 3 levels");
    println!("  Total files: {}", total_files);
    println!("  Findings: {}", findings.len());
    println!("  Time: {:?}", duration);
    println!("  Files/sec: {:.2}", total_files as f64 / duration.as_secs_f64());
    
    // Should find secrets in all files
    assert!(findings.len() >= total_files * 2, "Should find at least 2 secrets per file");
    
    // Should handle deep directories efficiently (under 3 seconds)
    assert!(
        duration < Duration::from_secs(3),
        "Deep directory scan should take less than 3 seconds, took {:?}",
        duration
    );
}

#[test]
fn test_scanning_performance_comparison() {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create test scenarios
    let scenarios = vec![
        ("few_secrets", create_file_with_few_secrets as fn(&Path)),
        ("many_secrets", create_file_with_many_secrets as fn(&Path)),
        ("no_secrets", create_file_with_no_secrets as fn(&Path)),
        ("large_no_secrets", create_large_file_with_no_secrets as fn(&Path)),
    ];
    
    let scanner = Scanner::new().unwrap();
    
    for (scenario_name, create_fn) in scenarios {
        let scenario_dir = temp_path.join(scenario_name);
        fs::create_dir_all(&scenario_dir).unwrap();
        
        create_fn(&scenario_dir);
        
        let start = Instant::now();
        let findings = scanner.scan_directory(&scenario_dir).unwrap();
        let duration = start.elapsed();
        
        println!("Scenario '{}': {} findings in {:?}", scenario_name, findings.len(), duration);
        
        // All scenarios should be reasonably fast
        assert!(
            duration < Duration::from_secs(2),
            "Scenario '{}' took too long: {:?}",
            scenario_name,
            duration
        );
    }
}

fn create_file_with_few_secrets(dir: &std::path::Path) {
    let content = r#"
const config = {
    api_url: "https://api.example.com",
    timeout: 5000,
    secret_key: "AKIAIOSFODNN7EXAMPLE"
};
"#;
    fs::write(dir.join("config.js"), content).unwrap();
}

fn create_file_with_many_secrets(dir: &std::path::Path) {
    let mut content = String::new();
    for i in 0..50 {
        content.push_str(&format!("const secret_{} = \"AKIA{:016}\";\n", i, i));
    }
    fs::write(dir.join("secrets.js"), content).unwrap();
}

fn create_file_with_no_secrets(dir: &std::path::Path) {
    let content = r#"
function processData(input) {
    const result = input.map(item => item.value * 2);
    return result.filter(value => value > 10);
}

const data = [
    { id: 1, value: 5 },
    { id: 2, value: 8 },
    { id: 3, value: 12 }
];

console.log(processData(data));
"#;
    fs::write(dir.join("clean.js"), content).unwrap();
}

fn create_large_file_with_no_secrets(dir: &std::path::Path) {
    let mut content = String::new();
    for i in 0..5000 {
        content.push_str(&format!("// Line {} with normal content\n", i));
        content.push_str(&format!("const variable_{} = \"normal_value_{}\";\n", i, i));
    }
    fs::write(dir.join("large_clean.js"), content).unwrap();
}