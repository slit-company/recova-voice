import { expect, test, type Page, type Route } from "@playwright/test";

const workflowPath = process.env.E2E_WORKFLOW_PATH ?? "/workflow/1";
const maskedMobile = "+82 **** 0000";

type Authority = {
    gates?: Record<string, boolean>;
    remaining?: number;
    proof?: boolean;
    registration?: boolean;
    media?: boolean;
    contained?: boolean;
    terminal?: string | null;
};

const authorityResponse = ({
    gates = { g0: true, g1: true, g2: true, g3: true, g4: true, g5: true },
    remaining = 3,
    proof = true,
    registration = true,
    media = true,
    contained = false,
    terminal = null,
}: Authority = {}, status = "verified") => ({
    session_id: 1,
    status,
    otp_required: false,
    masked_phone: maskedMobile,
    expires_at: "2030-01-01T00:00:00Z",
    gate_states: gates,
    remaining_attempts: remaining,
    proof_current: proof,
    registration_fresh: registration,
    media_fresh: media,
    contained,
    terminal_class: terminal,
});

const json = (route: Route, body: unknown, status = 200) => route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
});

async function mockAllNetwork(page: Page, authority: Authority = {}) {
    let actionCalls = 0;
    await page.route("**/*", async (route) => {
        const url = new URL(route.request().url());
        if (url.origin !== "http://127.0.0.1:3000" && url.origin !== "http://localhost:3000") {
            await route.abort("blockedbyclient");
            return;
        }
        if (!url.pathname.startsWith("/api/")) {
            await route.continue();
            return;
        }
        if (url.pathname.endsWith("/phone-preview/start")) {
            await json(route, { ...authorityResponse(authority, "pending_verification"), otp_required: true });
            return;
        }
        if (url.pathname.endsWith("/phone-preview/verify")) {
            await json(route, authorityResponse(authority));
            return;
        }
        if (url.pathname.includes("/phone-preview/status/") || /\/phone-preview\/\d+$/.test(url.pathname)) {
            await json(route, authorityResponse(authority));
            return;
        }
        if (url.pathname.endsWith("/phone-preview/call") || url.pathname.endsWith("/phone-preview/wait-inbound")) {
            actionCalls += 1;
            await new Promise((resolve) => setTimeout(resolve, 40));
            await json(route, authorityResponse({ ...authority, remaining: Math.max(0, (authority.remaining ?? 3) - 1) }, url.pathname.endsWith("wait-inbound") ? "awaiting_inbound" : "calling"));
            return;
        }
        if (url.pathname.endsWith("/phone-preview/contain")) {
            await json(route, authorityResponse({ ...authority, contained: true, terminal: "operator_containment" }, "failed"));
            return;
        }
        if (url.pathname.includes("/workflow/fetch/")) {
            await json(route, {
                id: 1,
                name: "Hermetic smoke",
                workflow_definition: { nodes: [], edges: [] },
                workflow_configurations: {},
                template_context_variables: {},
            });
            return;
        }
        await json(route, {});
    });
    return () => actionCalls;
}

async function openDialog(page: Page) {
    await page.goto(workflowPath);
    await page.getByRole("button", { name: /Call me preview|전화로 프리뷰/ }).click();
    await expect(page.getByTestId("staging-authority-panel")).not.toBeVisible();
}

async function prepareVerified(page: Page, mode: "outbound" | "inbound" = "outbound") {
    await openDialog(page);
    if (mode === "inbound") await page.getByRole("tab", { name: /I'll call Recova|내가 전화하기/ }).click();
    await page.locator("#preview-phone-number").fill("01000000000");
    await page.getByRole("button", { name: /Prepare verification|인증 준비/ }).click();
    await expect(page.getByText(maskedMobile)).toBeVisible();
    await expect(page.locator("body")).not.toContainText("01000000000");
    await page.locator("#preview-otp").fill("000000");
    await page.getByRole("button", { name: /Verify only|인증만 완료/ }).click();
    await expect(page.getByTestId("staging-authority-panel")).toBeVisible();
}

const assertNoUnsafeDom = async (page: Page) => {
    const body = await page.getByRole("dialog").innerText();
    expect(body).not.toMatch(/workflow[_ -]?run|session[_ -]?id|organization[_ -]?id|capability|digest|proxy|\bSIP\b|\bSDP\b|credential|token|api[_ -]?key/i);
    expect(body).not.toMatch(/010[- ]?\d{4}[- ]?\d{4}/);
    expect(body).not.toContain("Again");
    expect(body).not.toContain("다시");
};

test.describe("Onnuri private staging phone preview", () => {
    test("OTP and masking precede one outbound request; double submit is suppressed", async ({ page }) => {
        const actionCalls = await mockAllNetwork(page);
        await prepareVerified(page);
        const action = page.getByRole("button", { name: /Request one outbound attempt|발신 1회 요청/ });
        await action.dblclick();
        await expect.poll(actionCalls).toBe(1);
        await expect(page.getByText(/One outbound attempt was requested|발신 시도 1회를 요청/)).toBeVisible();
        await assertNoUnsafeDom(page);
    });

    test("inbound precommit stays authorized and pending, never answered", async ({ page }) => {
        await mockAllNetwork(page);
        await prepareVerified(page, "inbound");
        await page.getByRole("button", { name: /Authorize inbound waiting|수신 대기 승인/ }).click();
        await expect(page.getByText(/authorized and pending|승인되어 대기 중/).first()).toBeVisible();
        await expect(page.getByRole("dialog").getByText(/^(Answered|응답 완료)$/)).toHaveCount(0);
        await assertNoUnsafeDom(page);
    });

    for (const scenario of [
        { name: "a closed gate", authority: { gates: { g0: true, g1: false } } },
        { name: "stale proof", authority: { proof: false } },
        { name: "stale registration", authority: { registration: false } },
        { name: "stale media bounds", authority: { media: false } },
        { name: "exhaustion", authority: { remaining: 0 } },
        { name: "containment", authority: { contained: true } },
        { name: "terminal failure", authority: { terminal: "failed" } },
    ]) {
        test(`${scenario.name} exposes booleans and disables both call verbs`, async ({ page }) => {
            await mockAllNetwork(page, scenario.authority);
            await prepareVerified(page);
            const action = page.getByRole("button", { name: /Request one outbound attempt|발신 1회 요청/ });
            if (await action.count()) await expect(action).toBeDisabled();
            else await expect(action).toHaveCount(0);
            await expect(page.getByTestId("staging-authority-panel")).toBeVisible();
            await assertNoUnsafeDom(page);
        });
    }

    test("partition failure fails closed and exposes no retry verb", async ({ page }) => {
        await mockAllNetwork(page);
        await page.route("**/api/v1/phone-preview/status/**", (route) => route.abort("connectionfailed"));
        await prepareVerified(page);
        await expect(page.getByRole("alert")).toContainText(/failed closed|안전하게 거부/);
        await expect(page.getByRole("button", { name: /Again|다시/ })).toHaveCount(0);
    });

    test("wrong organization, role, and API key are deterministic 403 responses", async ({ page }) => {
        await mockAllNetwork(page);
        for (const reason of ["wrong-organization", "wrong-role", "api-key"]) {
            await page.route("**/api/v1/phone-preview/start", (route) => json(route, { detail: "phone_preview_requires_user_session" }, 403), { times: 1 });
            const status = await page.evaluate(async (denial) => {
                const response = await fetch("/api/v1/phone-preview/start", {
                    method: "POST",
                    headers: denial === "api-key"
                        ? { "Content-Type": "application/json", "X-API-Key": "" }
                        : { "Content-Type": "application/json", "X-Test-Denial": denial },
                    body: "{}",
                });
                return response.status;
            }, reason);
            expect(status).toBe(403);
        }
    });

    test("server-requested final acknowledgement is manual and never automatic", async ({ page }) => {
        await mockAllNetwork(page, { remaining: 1 });
        await page.route("**/api/v1/phone-preview/call", (route) => json(route, { detail: "manual_acknowledgement_required" }, 409), { times: 1 });
        await prepareVerified(page);
        await page.getByRole("button", { name: /Request one outbound attempt|발신 1회 요청/ }).click();
        const acknowledgement = page.getByRole("checkbox");
        await expect(acknowledgement).toBeVisible();
        await expect(page.getByRole("button", { name: /Request one outbound attempt|발신 1회 요청/ })).toBeDisabled();
        await acknowledgement.check();
        await expect(page.getByRole("button", { name: /Request one outbound attempt|발신 1회 요청/ })).toBeEnabled();
    });

    test("explicit containment removes all call actions", async ({ page }) => {
        await mockAllNetwork(page);
        await prepareVerified(page);
        await page.getByRole("button", { name: /Contain now|즉시 격리/ }).click();
        await expect(page.getByText(/Containment is active|격리가 활성화/)).toBeVisible();
        await expect(page.getByRole("button", { name: /Request one outbound attempt|발신 1회 요청/ })).toHaveCount(0);
        await assertNoUnsafeDom(page);
    });
});
