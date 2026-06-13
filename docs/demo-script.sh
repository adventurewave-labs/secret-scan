#!/bin/bash
# Demo script for creating SecretScan demo GIF
# Use with asciinema or terminalizer

echo "=== SecretScan Demo ==="
echo ""
echo "1. Installing SecretScan..."
echo "$ cargo install secretscan"
echo ""
sleep 2

echo "2. Creating a sample project with secrets..."
mkdir -p demo_project/src demo_project/config
cd demo_project

echo 'fn main() {
    let api_key = "AKIAIOSFODNN7EXAMPLE"; // AWS key
    println!("Starting application...");
}' > src/main.rs

echo 'DATABASE_URL=postgresql://user:password@localhost/mydb
GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a
STRIPE_KEY=sk_test_FAKE1234567890DEMO1234567890' > config/secrets.env

echo '# Test file with mock credentials
TEST_AWS_KEY=AKIAIOSFODNN7EXAMPLE
TEST_TOKEN=test_only_not_real' > src/test_secrets.rs

echo ""
sleep 1

echo "3. Running SecretScan..."
echo "$ secretscan"
echo ""
sleep 1

# Simulated output
echo -e "\033[33m⠋\033[0m Scanning files..."
sleep 0.5
echo -e "\033[33m⠹\033[0m Scanning files... [45/45]"
sleep 0.5
echo ""
echo -e "\033[31mWarning: Found 5 potential secrets:\033[0m"
echo ""
echo -e "\033[33mFile: src/main.rs\033[0m"
echo "line 2:     let api_key = \"AKIAIOSFODNN7EXAMPLE\"; // AWS key"
echo -e "Pattern: \033[31mAWS Access Key\033[0m"
echo "Match: AKIAIOSFODNN7EXAMPLE"
echo "Entropy: 3.7"
echo ""
echo -e "\033[33mFile: config/secrets.env\033[0m"
echo "line 1: DATABASE_URL=postgresql://user:password@localhost/mydb"
echo -e "Pattern: \033[31mDatabase URL\033[0m"
echo "Match: postgresql://user:password@localhost/mydb"
echo "Entropy: 4.2"
echo ""
echo "line 2: GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a"
echo -e "Pattern: \033[31mGitHub Personal Access Token\033[0m"
echo "Match: ghp_16C7e42F292c6912E7710c838347Ae178B4a"
echo "Entropy: 4.5"
echo ""
echo "line 3: STRIPE_KEY=sk_test_FAKE1234567890DEMO1234567890"
echo -e "Pattern: \033[31mStripe API Key\033[0m"
echo "Match: sk_test_FAKE1234567890DEMO1234567890"
echo "Entropy: 4.3"
echo ""
sleep 2

echo "4. Using --skip-tests flag to reduce false positives..."
echo "$ secretscan --skip-tests"
echo ""
sleep 1

echo -e "\033[33m⠋\033[0m Scanning files..."
sleep 0.5
echo -e "\033[33m⠹\033[0m Scanning files... [45/45]"
sleep 0.5
echo ""
echo -e "\033[31mWarning: Found 4 potential secrets:\033[0m"
echo "(Test file src/test_secrets.rs was skipped)"
echo ""
sleep 2

echo "5. Outputting as JSON for CI/CD integration..."
echo "$ secretscan --format json --output scan-results.json"
echo ""
sleep 1
echo -e "\033[32m✓\033[0m Results written to scan-results.json"
echo ""
echo "$ cat scan-results.json | jq '.[] | .pattern_name'"
echo "\"AWS Access Key\""
echo "\"Database URL\""
echo "\"GitHub Personal Access Token\""
echo "\"Stripe API Key\""
echo ""
sleep 2

echo "=== Demo Complete ==="
echo ""
echo "SecretScan: Fast, accurate, and easy to use!"
echo "Install: cargo install secretscan"
echo "Docs: https://docs.secretscan.io"

# Cleanup
cd ..
rm -rf demo_project

# Instructions for creating GIF:
# 1. Install asciinema: brew install asciinema
# 2. Record: asciinema rec demo.cast
# 3. Run this script
# 4. Convert to GIF: docker run --rm -v $PWD:/data asciinema/asciicast2gif demo.cast demo.gif
# Or use terminalizer for direct GIF recording