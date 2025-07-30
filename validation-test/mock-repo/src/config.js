// Configuration file with various secrets
const config = {
  // AWS Configuration
  AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7PRODKEY",
  AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODKEY",
  
  // Database connections
  DATABASE_URL: "postgresql://produser:prodpass123@prod-db:5432/maindb",
  MONGO_URL: "mongodb://mongouser:mongopass@mongo-cluster:27017/production",
  REDIS_URL: "redis://redisuser:redispass@redis-cluster:6379/1",
  
  // API Keys
  GOOGLE_API_KEY: "AIzaSyBvOiM71gGZdY9lQPzPzPzPzPzPzPzPzPzP",
  STRIPE_SECRET_KEY: "sk_live_abcdefghijklmnopqrstuvwxyz123456789",
  SENDGRID_API_KEY: "SG.abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyz",
  
  // GitHub tokens
  GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
  GITHUB_OAUTH_SECRET: "GOCSPX-abcdefghijklmnopqrstuvwxyz1234567890",
  
  // Slack integration
  SLACK_BOT_TOKEN: "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwxyz",
  SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T1234567890/B1234567890/abcdefghijklmnopqrstuvwxyz",
  
  // JWT Secret
  JWT_SECRET: "your-256-bit-secret-key-here-must-be-long-enough",
  
  // Other sensitive data
  ENCRYPTION_KEY: "aes256-encryption-key-32-characters",
  HASH_SALT: "bcrypt-salt-with-sufficient-entropy-12345",
  
  // Obfuscated secrets (should still be detected)
  ENCODED_SECRET: Buffer.from("secret-api-key-encoded", 'utf8').toString('base64'),
  HEX_ENCODED: "736563726574746f6b656e696e686578",
  
  // Test data that should be ignored with --skip-tests
  TEST_API_KEY: "test_sk_1234567890abcdefghijklmnopqrstuvwxyz",
};

module.exports = config;