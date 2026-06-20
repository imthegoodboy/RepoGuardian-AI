module.exports = {
  testDir: "./tests/e2e",
  testMatch: "**/*.spec.cjs",
  timeout: 210000,
  workers: 1,
  reporter: "line",
  use: {
    browserName: "chromium",
    viewport: { width: 1440, height: 900 },
  },
};
