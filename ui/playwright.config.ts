import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:3000";

export default defineConfig({
    testDir: "./e2e",
    fullyParallel: false,
    forbidOnly: true,
    retries: 0,
    workers: 1,
    timeout: 30_000,
    expect: { timeout: 5_000 },
    use: {
        baseURL,
        trace: "off",
        screenshot: "off",
        video: "off",
        serviceWorkers: "block",
    },
    webServer: process.env.PLAYWRIGHT_BASE_URL
        ? undefined
        : {
            command: "npm run dev -- --hostname 127.0.0.1",
            url: baseURL,
            reuseExistingServer: false,
            timeout: 120_000,
        },
    projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
