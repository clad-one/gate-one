import { defineConfig, devices } from "@playwright/test";

// Requires the local Compose stack:
//   make e2e-up
// All hosts are *.localhost (loopback), so run the browser on the
// Docker host (WSL with Docker Desktop integration works).
export default defineConfig({
  testDir: "./specs",
  timeout: 30_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: "http://app.mycompany.localhost:8080",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
