// Test data file - should be ignored with --skip-tests flag
const testSecrets = {
  // These should be ignored during scanning with --skip-tests
  TEST_AWS_KEY: "AKIAIOSFODNN7TESTKEY",
  TEST_GITHUB_TOKEN: "ghp_test1234567890abcdefghijklmnopqrstuvwxyz",
  TEST_STRIPE_KEY: "sk_test_1234567890abcdefghijklmnopqrstuvwxyz",
  
  // Mock test data
  MOCK_SECRET: "mock-secret-for-testing-purposes-only",
  FAKE_API_KEY: "fake_api_key_abcdefghijklmnopqrstuvwxyz",
};

module.exports = testSecrets;