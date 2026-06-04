# Korean Locale Fallback Audit And Fix

## TL;DR
> Summary:      Add a strict UI localization test and browser-QA harness, then eliminate high-confidence English fallback text from Korean mode across the workflow editor, widget setup, voice selection, file upload, filters, and superadmin runs surfaces.
> Deliverables:
> - Locale-aware component tests and a static English-leak audit for UI text.
> - Real Chrome Korean-mode browser QA with screenshots for the fixed surfaces.
> - Localized React-owned UI copy routed through the translation catalog instead of relying on DOM patches.
> - A narrowed DOM override allowlist for genuinely runtime/generated text.
> Effort:       Large
> Risk:         High - the UI has no general test harness today and several target components are large, mixed-responsibility files.

## Scope
### Must have
- Add a deterministic UI localization test harness because `ui/package.json:5-12` currently exposes `dev`, `build`, `lint`, `generate-client`, and `test:display-options`, but no general UI test command.
- Preserve the existing app-wide locale flow: `LocaleProvider` reads `localStorage` and persisted `userConfig.ui_language` at `ui/src/context/LocaleContext.tsx:53-75`, updates `<html lang>` at `ui/src/context/LocaleContext.tsx:77-79`, enables Korean DOM overrides at `ui/src/context/LocaleContext.tsx:81-84`, and provides `t()` at `ui/src/context/LocaleContext.tsx:86-92`.
- Keep persisted language behavior compatible with the settings page, which saves `ui_language` at `ui/src/app/settings/page.tsx:29-41` and renders the language picker at `ui/src/app/settings/page.tsx:56-64`.
- Keep the backend/user-config contract intact because user config fetch/save is wired at `ui/src/context/UserConfigContext.tsx:105-173`, the API schema constrains `ui_language` to `"en" | "ko"` at `api/schemas/user_configuration.py:25`, and merge/masking preserve it at `api/services/configuration/merge.py:77-78` and `api/services/configuration/masking.py:139`.
- Move React-owned visible strings to keyed translations. The current translation table starts at `ui/src/lib/i18n.ts:25`, derives keys from English at `ui/src/lib/i18n.ts:1537`, and falls back to English at `ui/src/lib/i18n.ts:1539-1552`.
- Reduce reliance on exact-match Korean DOM patches. Current overrides are exact strings at `ui/src/lib/ko-dom-overrides.ts:1-24`, patch attributes listed at `ui/src/lib/ko-dom-overrides.ts:526-532`, skip code/input-like nodes at `ui/src/lib/ko-dom-overrides.ts:534-537`, and run through a `MutationObserver` at `ui/src/lib/ko-dom-overrides.ts:582-617`.
- Audit and fix these high-confidence untranslated surfaces:
  - Workflow configurations dialog: `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:84-304`.
  - Widget/embed dialog: `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:50-610`.
  - Workflow editor header: `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:98-152`, `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:186-208`, and `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:235-388`.
  - Voice selector: `ui/src/components/VoiceSelector.tsx:64-93`, `ui/src/components/VoiceSelector.tsx:169-175`, and `ui/src/components/VoiceSelector.tsx:208-381`.
  - Dictionary/template/voicemail dialogs: `ui/src/app/workflow/[workflowId]/components/DictionaryDialog.tsx:42-76`, `ui/src/app/workflow/[workflowId]/components/TemplateContextVariablesDialog.tsx:70-146`, and `ui/src/app/workflow/[workflowId]/components/VoicemailDetectionDialog.tsx:111-201`.
  - Document upload: `ui/src/app/files/DocumentUpload.tsx:36-49`, `ui/src/app/files/DocumentUpload.tsx:51-64`, `ui/src/app/files/DocumentUpload.tsx:103-142`, and `ui/src/app/files/DocumentUpload.tsx:181-303`.
  - Filter builder and filter controls: `ui/src/components/filters/FilterBuilder.tsx:177-209`, `ui/src/components/filters/FilterBuilder.tsx:295-457`, `ui/src/components/filters/MultiSelectFilter.tsx:53-57`, and `ui/src/components/filters/MultiSelectFilter.tsx:59-153`.
  - Superadmin runs page: `ui/src/app/superadmin/runs/page.tsx:277-340`, `ui/src/app/superadmin/runs/page.tsx:348-380`, `ui/src/app/superadmin/runs/page.tsx:449-462`, and `ui/src/app/superadmin/runs/page.tsx:571-620`.
- Respect UI project guidance: `ui/AGENTS.md:1-6` says this is a Recova frontend on a Dograh workflow-builder base, `ui/AGENTS.md:45-56` prioritizes Korean B2B operational screens and high-risk campaign/report/usage/settings/telephony/superadmin states, and `ui/AGENTS.md:58-65` marks `src/client/` as generated.
- Use primary-source implementation constraints:
  - Next.js client components are required for state, effects, event handlers, and browser APIs like `localStorage`: https://nextjs.org/docs/app/building-your-application/rendering/client-components
  - The `'use client'` directive defines the client boundary for interactive UI: https://nextjs.org/docs/app/api-reference/directives/use-client
  - React effects run only on the client, which is relevant to localStorage-backed locale state: https://react.dev/reference/react/useEffect
  - React context must be consumed under the matching provider: https://react.dev/reference/react/useContext
  - Playwright locator assertions auto-retry and should be used for visible text checks: https://playwright.dev/docs/test-assertions
  - Playwright screenshots should capture browser evidence: https://playwright.dev/docs/screenshots

### Must NOT have (guardrails, anti-slop, scope boundaries)
- Do not perform a blind English-to-Korean or Dograh-to-Recova replacement. Project-level instructions explicitly warn against blind rebranding, and `ui/AGENTS.md:50-51` says not to introduce Recova branding into links or support destinations unless the destination is Recova-ready.
- Do not hand-edit generated client files under `ui/src/client/`; `ui/AGENTS.md:58-65` marks that directory generated and `ui/src/client/client.gen.ts:1` confirms generation by `@hey-api/openapi-ts`.
- Do not translate protocol identifiers, provider names, API enum values, code snippets, URLs, CSS class names, environment variables, telemetry dataset names, or compatibility identifiers such as `dograh-inline-container` at `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:133` and `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:496-523`.
- Do not translate `DEFAULT_VOICEMAIL_SYSTEM_PROMPT` blindly. It is marked as matching Pipecat behavior at `ui/src/app/workflow/[workflowId]/components/VoicemailDetectionDialog.tsx:23-44`; localize surrounding labels/help text, not the model contract unless backend/pipecat prompt migration is explicitly in scope.
- Do not add production-visible test-only routes or explanatory UI copy. Browser QA should use authenticated/mocked test traffic, component tests, or Playwright fixtures rather than shipping a hidden QA page.
- Do not make Korean DOM overrides the primary fix for React-owned text. Use `t()` for components; reserve `ko-dom-overrides.ts` for generated/runtime strings the React owner cannot localize cleanly.
- Do not leave touched TypeScript/TSX files larger than 250 pure LOC after adding new logic. `ui/src/lib/i18n.ts:1537-1552`, `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:50-610`, `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:52-507`, `ui/src/components/VoiceSelector.tsx:28-388`, `ui/src/components/filters/FilterBuilder.tsx:44-458`, and `ui/src/app/superadmin/runs/page.tsx:284-620` are already large enough that localization work should either be replacement-only or include a focused split.

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: TDD + Vitest/React Testing Library/jsdom for helper and component coverage; Playwright real Chrome for Korean-mode browser QA; existing Next build as the integration gate.
- QA policy: every task has agent-executed scenarios, red evidence before production fixes, green evidence after, and browser screenshots for user-visible surfaces.
- Evidence: `evidence/task-<N>-<slug>.<ext>`

## Execution strategy
### Parallel execution waves
> Target 5-8 tasks per wave. <3 per wave (except final) = under-splitting.
> Extract shared dependencies as Wave-1 tasks to maximize parallelism.

Wave 1 (no dependencies):
- Task 1: Add locale test/QA harness and split the oversized translation catalog into owned message modules.
- Task 2: Add static English fallback inventory gate and scoped allowlist.

Wave 2 (after Wave 1):
- Task 3: depends [1, 2] - localize workflow editor header and header state text.
- Task 4: depends [1, 2] - localize workflow configurations dialog.
- Task 5: depends [1, 2] - localize widget/embed dialog.
- Task 6: depends [1, 2] - localize voice selector.
- Task 7: depends [1, 2] - localize dictionary, template variables, and voicemail dialogs.
- Task 8: depends [1, 2] - localize document upload plus shared filter builder/controls.

Wave 3 (after Wave 2):
- Task 9: depends [1, 2, 8] - localize superadmin runs page and superadmin-facing filter data.
- Task 10: depends [3, 4, 5, 6, 7, 8, 9] - tighten DOM overrides, `<html lang>` behavior, full audit, and browser QA coverage.

Critical path: Task 1 -> Task 2 -> Task 8 -> Task 9 -> Task 10

### Dependency matrix
| Task | Depends on | Blocks | Can parallelize with |
|------|------------|--------|----------------------|
| 1    | none       | 2, 3, 4, 5, 6, 7, 8, 10 | none |
| 2    | 1          | 3, 4, 5, 6, 7, 8, 9, 10 | none |
| 3    | 1, 2       | 10     | 4, 5, 6, 7, 8 |
| 4    | 1, 2       | 10     | 3, 5, 6, 7, 8 |
| 5    | 1, 2       | 10     | 3, 4, 6, 7, 8 |
| 6    | 1, 2       | 10     | 3, 4, 5, 7, 8 |
| 7    | 1, 2       | 10     | 3, 4, 5, 6, 8 |
| 8    | 1, 2       | 9, 10  | 3, 4, 5, 6, 7 |
| 9    | 1, 2, 8    | 10     | none |
| 10   | 3, 4, 5, 6, 7, 8, 9 | final verification | none |

## Todos
> Implementation + Test = ONE task. Never separate.
> Every task MUST have: References + Acceptance Criteria + QA Scenarios + Commit.

- [ ] 1. Add locale test/QA harness and modular translation catalogs

  What to do: Add UI test infrastructure with Vitest, React Testing Library, jest-dom, jsdom, and Playwright real Chrome config. Add scripts in `ui/package.json`: `test:i18n`, `test:locale-audit`, `test:e2e:locale`, and `test:locale`. Create `ui/vitest.config.mts`, `ui/src/test/setup.ts`, `ui/e2e/locale-korean.spec.ts`, and shared test helpers for rendering under `LocaleProvider` with mocked `UserConfigContext`. Refactor `ui/src/lib/i18n.ts` so language/types/translate stay in `i18n.ts`, while message catalogs move into focused modules under `ui/src/lib/i18n/messages/`. Preserve `TranslationKey = keyof messages.en` compatibility and English fallback behavior while tests pin it. Write tests first for `translate()`, interpolation, Korean key lookup, English fallback, and localStorage/user-config language precedence; capture the first red run before refactoring.
  Must NOT do: Do not change user-facing copy in this task except mechanically moving existing catalog strings. Do not edit `ui/src/client/**`. Do not add production-visible QA routes.

  Parallelization: Can parallel: NO | Wave 1 | Blocks: [2, 3, 4, 5, 6, 7, 8, 10] | Blocked by: []

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/scripts/test-display-options.mts:1-9` - current Node 24+ script pattern and evidence style for UI-side checks.
  - Pattern:  `ui/package.json:5-12` - existing scripts; add new localization test scripts here.
  - Pattern:  `ui/src/context/LocaleContext.tsx:53-92` - locale source of truth, `localStorage`, persisted config sync, DOM override activation, and `t()`.
  - Pattern:  `ui/src/context/LocaleContext.tsx:149-154` - provider guard behavior that tests must preserve.
  - Pattern:  `ui/src/lib/i18n.ts:1-23` - language types, defaults, labels, locale tags.
  - Pattern:  `ui/src/lib/i18n.ts:25-1535` - existing monolithic messages to move without copy changes.
  - Pattern:  `ui/src/lib/i18n.ts:1537-1552` - `TranslationKey` and `translate()` contract to preserve.
  - Pattern:  `ui/src/app/layout.tsx:63-82` - provider nesting where locale is mounted app-wide.
  - API/Type: `api/schemas/user_configuration.py:25` - `ui_language` allowed values.
  - API/Type: `ui/src/context/UserConfigContext.tsx:105-173` - user config fetch/save behavior used by locale state.
  - External: `https://nextjs.org/docs/app/api-reference/directives/use-client` - interactive state and browser API boundaries.
  - External: `https://react.dev/reference/react/useEffect` - client-only effect behavior for localStorage/hydration.
  - External: `https://react.dev/reference/react/useContext` - context provider/consumer contract.
  - External: `https://playwright.dev/docs/test-assertions` - auto-retrying UI assertions.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run src/lib/i18n/__tests__/translate.test.tsx 2>&1 | tee ../evidence/task-1-locale-harness-green.txt` exits 0 after an earlier red log is captured at `evidence/task-1-locale-harness-red.txt`.
  - [ ] `cd ui && npm run test:e2e:locale -- --list 2>&1 | tee ../evidence/task-1-playwright-list.txt` lists the Chrome project and Korean locale spec without launching the full app.
  - [ ] `cd ui && npm run build 2>&1 | tee ../evidence/task-1-build.txt` exits 0.
  - [ ] `git diff --check 2>&1 | tee evidence/task-1-diff-check.txt` exits 0.
  - [ ] `node -e "const fs=require('fs'); const p='ui/src/lib/i18n.ts'; const n=fs.readFileSync(p,'utf8').split('\\n').filter(l=>l.trim()&&!l.trim().startsWith('//')).length; if(n>250){throw new Error(p+' pure LOC '+n)}"` exits 0, or the evidence documents that `i18n.ts` contains only type/export orchestration and no expanded catalog data.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Locale helper and provider contract are green
    Tool:     bash
    Steps:    mkdir -p evidence && cd ui && npm run test:i18n -- --run src/lib/i18n/__tests__/translate.test.tsx src/context/__tests__/LocaleContext.test.tsx 2>&1 | tee ../evidence/task-1-locale-harness.txt
    Expected: Command exits 0; evidence includes passing tests for English, Korean, interpolation, fallback, localStorage, persisted ui_language, and provider guard.
    Evidence: evidence/task-1-locale-harness.txt

  Scenario: Missing Korean key still falls back predictably
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run src/lib/i18n/__tests__/translate.test.tsx -t "falls back to English for a missing Korean key" 2>&1 | tee ../evidence/task-1-fallback-edge.txt
    Expected: Command exits 0 and the assertion proves fallback behavior is intentional, not accidental.
    Evidence: evidence/task-1-fallback-edge.txt
  ```

  Commit: YES | Message: `test(ui): add locale harness and modular catalogs` | Files: [`ui/package.json`, `ui/package-lock.json`, `ui/vitest.config.mts`, `ui/playwright.locale.config.ts`, `ui/src/test/**`, `ui/e2e/locale-korean.spec.ts`, `ui/src/lib/i18n.ts`, `ui/src/lib/i18n/messages/**`]

- [ ] 2. Add static English fallback inventory gate and allowlist

  What to do: Add `ui/scripts/audit-locale-fallback.mts` using the TypeScript compiler API to scan `ui/src/app/**`, `ui/src/components/**`, `ui/src/context/**`, and `ui/src/lib/**` for high-confidence English UI strings in JSX text, accessible names, placeholders, toast/alert strings, `DialogTitle`, `DialogDescription`, labels, buttons, and table headers. Add a focused allowlist for technical names, code examples, env vars, URLs, provider IDs, API enum values, and compatibility identifiers. Make the first red run identify the known surfaces from Scope, then save that known set as a reviewed baseline so later tasks can fail only on newly introduced findings while they burn down the baseline. The final gate in Task 10 must run without the baseline and fail on any remaining unexplained high-confidence English UI literal.
  Must NOT do: Do not use a regex-only scanner for TSX. Do not allowlist whole directories except generated `ui/src/client/**` and static compatibility assets. Do not fail on user-provided values, database data, provider names, or code snippets.

  Parallelization: Can parallel: NO | Wave 1 | Blocks: [3, 4, 5, 6, 7, 8, 9, 10] | Blocked by: [1]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/scripts/test-display-options.mts:11-50` - Node script structure with explicit pass/fail exit code.
  - Pattern:  `ui/AGENTS.md:58-65` - generated client exclusion and `npm run generate-client` rule.
  - Pattern:  `ui/src/client/client.gen.ts:1` - generated-file marker.
  - Pattern:  `ui/public/embed/dograh-widget.js` - static embed compatibility asset; do not blanket translate.
  - Pattern:  `ui/src/lib/ko-dom-overrides.ts:526-617` - runtime DOM override behavior to compare against static audit results.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:432-535` - code/example blocks that should be partially allowlisted, not treated like normal UI text.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/VoicemailDetectionDialog.tsx:23-44` - prompt contract allowlist.
  - External: `https://playwright.dev/docs/test-assertions` - locator text assertions should complement the static gate.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && node scripts/audit-locale-fallback.mts --format=json --fail-on=high 2>&1 | tee ../evidence/task-2-locale-audit-red.json; test ${PIPESTATUS[0]} -ne 0` proves the raw gate fails before production localization fixes.
  - [ ] `cd ui && node scripts/audit-locale-fallback.mts --format=json --write-baseline scripts/locale-fallback-baseline.json 2>&1 | tee ../evidence/task-2-baseline-write.txt` exits 0 and writes a reviewed baseline of known noncompliant strings.
  - [ ] `cd ui && npm run test:locale-audit 2>&1 | tee ../evidence/task-2-npm-script.txt` exits 0 by comparing against `scripts/locale-fallback-baseline.json` and failing only on newly introduced findings.
  - [ ] The JSON evidence contains per-finding `file`, `line`, `kind`, `text`, and `reason` fields, and allowlisted or baselined findings include a non-empty reason.
  - [ ] The scanner excludes `ui/src/client/**` but does not exclude `ui/src/app/**` or `ui/src/components/**`.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Known English leaks fail the gate before fixes
    Tool:     bash
    Steps:    mkdir -p evidence && cd ui && node scripts/audit-locale-fallback.mts --format=json --fail-on=high 2>&1 | tee ../evidence/task-2-locale-audit-red.json; test ${PIPESTATUS[0]} -ne 0
    Expected: Command pipeline proves the scanner exits non-zero and includes at least ConfigurationsDialog, EmbedDialog, WorkflowEditorHeader, VoiceSelector, DocumentUpload, FilterBuilder, and superadmin runs findings.
    Evidence: evidence/task-2-locale-audit-red.json

  Scenario: Technical allowlist does not hide visible labels
    Tool:     bash
    Steps:    cd ui && node scripts/audit-locale-fallback.mts --format=json --print-allowlist 2>&1 | tee ../evidence/task-2-allowlist.txt
    Expected: Evidence lists allowlist reasons for `dograh-inline-container`, API/status enum values, URLs, provider IDs, and the voicemail system prompt; visible labels like "Configure Widget" are not allowlisted.
    Evidence: evidence/task-2-allowlist.txt
  ```

  Commit: YES | Message: `test(ui): add Korean locale leak audit` | Files: [`ui/scripts/audit-locale-fallback.mts`, `ui/scripts/locale-fallback-baseline.json`, `ui/package.json`, `ui/package-lock.json`, `ui/src/lib/i18n/allowlist/**`]

- [ ] 3. Localize workflow editor header and header state text

  What to do: Write failing tests for Korean mode covering publish/duplicate toasts, UUID copy toasts, rename empty/error states, mobile menu/rename accessible labels, historical-version banner, back-to-draft, unsaved changes, validation error count/title, node/edge labels, and dropdown actions. Then route all React-owned header strings through `useLocale().t()`. If adding logic to the large header, extract focused subcomponents/hooks first so the touched logic stays reviewable.
  Must NOT do: Do not translate workflow names, workflow IDs, validation messages returned by the backend, version labels, UUIDs, or downloaded JSON content. Do not change navigation or save/publish behavior.

  Parallelization: Can parallel: YES | Wave 2 | Blocks: [10] | Blocked by: [1, 2]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:30-31` - already imports and consumes `useLocale()`.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:98-152` - hardcoded publish/duplicate/copy toast copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:186-208` - rename validation and failure copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:235-388` - visible/accessible header labels and validation popover.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx:424-496` - existing translated action labels to follow.
  - API/Type: `ui/src/client/types.gen.ts` - `WorkflowError` shape imported at `WorkflowEditorHeader.tsx:13`.
  - Test:     `ui/src/test/setup.ts` - render/test setup from Task 1.
  - External: `https://playwright.dev/docs/locators` - role/name assertions for buttons and menus.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/WorkflowEditorHeader.locale.test.tsx' 2>&1 | tee ../evidence/task-3-header-green.txt` exits 0 after a red run is captured at `evidence/task-3-header-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope workflow-header 2>&1 | tee ../evidence/task-3-header-audit.txt` exits 0.
  - [ ] Korean assertions include exact strings for publish, duplicate, unsaved changes, validation errors, back to draft, view runs, download, and copy Agent UUID.
  - [ ] English assertions still include the original English UI strings when `language="en"`.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Workflow header Korean mode
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@workflow-header" 2>&1 | tee ../evidence/task-3-header-browser.txt
    Expected: Browser test opens the mocked workflow editor in Korean mode, sees Korean header actions and no visible "Unsaved changes", "Validation Errors", "Back to Draft", "Publishing...", or "Failed to publish workflow" strings.
    Evidence: evidence/task-3-header-browser.txt and evidence/task-3-header.png

  Scenario: Backend validation text is not mistranslated
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/WorkflowEditorHeader.locale.test.tsx' -t "keeps backend validation messages unchanged" 2>&1 | tee ../evidence/task-3-header-edge.txt
    Expected: Command exits 0 and proves backend-provided `error.message` remains exact while surrounding labels are Korean.
    Evidence: evidence/task-3-header-edge.txt
  ```

  Commit: YES | Message: `fix(ui): localize workflow editor header` | Files: [`ui/src/app/workflow/[workflowId]/components/WorkflowEditorHeader.tsx`, `ui/src/app/workflow/[workflowId]/components/**/WorkflowEditorHeader*.tsx`, `ui/src/lib/i18n/messages/workflow*.ts`, `ui/src/app/workflow/[workflowId]/components/__tests__/WorkflowEditorHeader.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 4. Localize workflow configurations dialog

  What to do: Add failing tests for the configurations dialog in Korean mode. Localize dialog title, section headings, descriptions, labels, placeholders, select placeholders/items, conditional strategy descriptions, defaults, cancel/save/saving copy, and error logging/toast text if visible. Preserve numeric bounds and configuration payload shape. If line count grows, extract small presentational sections for name, ambient noise, turn detection, context compaction, and call management.
  Must NOT do: Do not translate stored enum values like `transcription` or `turn_analyzer`. Do not change defaults such as max call duration 600, idle timeout 10, smart turn stop 2, or ambient volume 0.3.

  Parallelization: Can parallel: YES | Wave 2 | Blocks: [10] | Blocked by: [1, 2]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:19-50` - state defaults and config fields to preserve.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:84-112` - title and agent name copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:114-159` - ambient noise copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:161-220` - turn detection copy and conditional descriptions.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:223-242` - context compaction copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx:244-304` - call management and footer copy.
  - API/Type: `ui/src/types/workflow-configurations.ts` - configuration types imported at `ConfigurationsDialog.tsx:9`.
  - Test:     `ui/src/test/setup.ts` - render/test setup from Task 1.
  - External: `https://react.dev/reference/react/useContext` - consume locale through provider.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/ConfigurationsDialog.locale.test.tsx' 2>&1 | tee ../evidence/task-4-config-dialog-green.txt` exits 0 after a red run is captured at `evidence/task-4-config-dialog-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope configurations-dialog 2>&1 | tee ../evidence/task-4-config-dialog-audit.txt` exits 0.
  - [ ] Tests assert both select branches: transcription-based and smart turn analyzer descriptions.
  - [ ] Tests assert `onSave` receives unchanged config keys and enum values after localized render.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Configurations dialog Korean mode
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@configurations-dialog" 2>&1 | tee ../evidence/task-4-config-dialog-browser.txt
    Expected: Browser opens the workflow configurations dialog in Korean mode, toggles smart turn analyzer, and finds no visible "Configurations", "Agent Name", "Ambient Noise", "Turn Detection", "Context Compaction", "Call Management", "Cancel", "Saving...", or "Save" labels.
    Evidence: evidence/task-4-config-dialog-browser.txt and evidence/task-4-config-dialog.png

  Scenario: Config payload remains stable
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/ConfigurationsDialog.locale.test.tsx' -t "saves unchanged configuration values from Korean UI" 2>&1 | tee ../evidence/task-4-config-dialog-payload.txt
    Expected: Command exits 0 and proves localized labels do not alter saved numeric/default/enum payload.
    Evidence: evidence/task-4-config-dialog-payload.txt
  ```

  Commit: YES | Message: `fix(ui): localize workflow configuration dialog` | Files: [`ui/src/app/workflow/[workflowId]/components/ConfigurationsDialog.tsx`, `ui/src/app/workflow/[workflowId]/components/**/Configurations*.tsx`, `ui/src/lib/i18n/messages/workflowConfigurations.ts`, `ui/src/app/workflow/[workflowId]/components/__tests__/ConfigurationsDialog.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 5. Localize widget/embed dialog

  What to do: Add failing tests for all widget modes in Korean mode: disabled state, enable embedding, allowed domains, floating/inline/headless mode cards, shared configuration fields, previews, save states, embed code copy states, and integration instruction headings. Split the large dialog before adding translation logic if needed: keep API load/save state in one hook and move mode cards, configuration fields, preview, instructions, and embed code into focused components. Localize UI labels and descriptions through `t()`, while leaving code examples, JS API names, token scripts, domain examples, color literals, and compatibility container IDs unchanged.
  Must NOT do: Do not translate or rename `window.RecovaWidget`, `dograh-inline-container`, generated embed scripts, status enum values in code examples, domain examples like `example.com`, or documentation URLs.

  Parallelization: Can parallel: YES | Wave 2 | Blocks: [10] | Blocked by: [1, 2]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:50-70` - component state and default visible strings.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:71-151` - API load/save behavior to preserve.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:177-199` - dialog title/docs/description.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:207-276` - enable toggle and allowed domains.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:278-331` - mode cards.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:333-430` - configuration and previews.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:432-535` - integration instructions and code blocks.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx:543-600` - save/embed-code states.
  - Pattern:  `ui/src/constants/documentation.ts` - widget mode documentation URLs imported at `EmbedDialog.tsx:28`.
  - API/Type: `ui/src/client/sdk.gen.ts` - embed token API functions imported at `EmbedDialog.tsx:4-8`.
  - External: `https://nextjs.org/docs/app/building-your-application/rendering/client-components` - API-driven interactive dialog must remain a client component.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/EmbedDialog.locale.test.tsx' 2>&1 | tee ../evidence/task-5-embed-dialog-green.txt` exits 0 after a red run is captured at `evidence/task-5-embed-dialog-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope embed-dialog 2>&1 | tee ../evidence/task-5-embed-dialog-audit.txt` exits 0.
  - [ ] Tests cover `floating`, `inline`, and `headless` modes.
  - [ ] Tests prove code examples still contain `window.RecovaWidget.start()`, `onStatusChange`, and `dograh-inline-container`.
  - [ ] Copy-to-clipboard state is localized while copied embed script content remains byte-identical to API fixture.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Widget dialog Korean mode across all modes
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@embed-dialog" 2>&1 | tee ../evidence/task-5-embed-dialog-browser.txt
    Expected: Browser opens widget dialog in Korean mode, switches floating/inline/headless, screenshots each mode, and sees no visible "Configure Widget", "Enable Embedding", "Allowed Domains", "Embed Mode", "Configuration", "Integration Instructions", "Save Configurations", "Embed Code", or "Copy Code" labels outside code blocks.
    Evidence: evidence/task-5-embed-dialog-browser.txt and evidence/task-5-embed-dialog-*.png

  Scenario: Technical widget API strings remain unchanged
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/EmbedDialog.locale.test.tsx' -t "preserves widget API examples and compatibility identifiers" 2>&1 | tee ../evidence/task-5-embed-dialog-technical.txt
    Expected: Command exits 0 and proves code snippets/container IDs are not localized or renamed.
    Evidence: evidence/task-5-embed-dialog-technical.txt
  ```

  Commit: YES | Message: `fix(ui): localize widget embed dialog` | Files: [`ui/src/app/workflow/[workflowId]/components/EmbedDialog.tsx`, `ui/src/app/workflow/[workflowId]/components/embed/**`, `ui/src/lib/i18n/messages/embed.ts`, `ui/src/app/workflow/[workflowId]/components/__tests__/EmbedDialog.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 6. Localize voice selector

  What to do: Add failing tests for providers with and without voice endpoints, manual-input mode, loading, fetch error, empty results, search placeholder, selected voice fallback, manual checkbox text, and count summary. Localize only UI chrome. Preserve provider IDs and returned voice metadata unless the value is one of the component-owned fallback strings.
  Must NOT do: Do not translate `voice.name`, `voice.description`, `voice.accent`, `voice.gender`, `voice.language`, provider IDs, or API request parameters. Do not change audio preview behavior.

  Parallelization: Can parallel: YES | Wave 2 | Blocks: [10] | Blocked by: [1, 2]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/components/VoiceSelector.tsx:15-18` - provider IDs are technical values.
  - Pattern:  `ui/src/components/VoiceSelector.tsx:64-93` - API fetch and hardcoded error text.
  - Pattern:  `ui/src/components/VoiceSelector.tsx:169-175` - selected voice fallback text.
  - Pattern:  `ui/src/components/VoiceSelector.tsx:208-245` - non-MPS/manual input UI.
  - Pattern:  `ui/src/components/VoiceSelector.tsx:248-381` - popover UI, loading/empty/search/count copy.
  - API/Type: `ui/src/client/types.gen.ts` - `VoiceInfo` imported at `VoiceSelector.tsx:7`.
  - External: `https://playwright.dev/docs/locators` - popover and combobox assertions.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run src/components/__tests__/VoiceSelector.locale.test.tsx 2>&1 | tee ../evidence/task-6-voice-selector-green.txt` exits 0 after a red run is captured at `evidence/task-6-voice-selector-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope voice-selector 2>&1 | tee ../evidence/task-6-voice-selector-audit.txt` exits 0.
  - [ ] Tests assert no translation of returned voice names/descriptions and provider IDs.
  - [ ] Tests assert singular/plural or count wording for the available voices footer in Korean.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Voice selector Korean mode
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@voice-selector" 2>&1 | tee ../evidence/task-6-voice-selector-browser.txt
    Expected: Browser opens a workflow config surface with the voice selector in Korean mode, searches voices, toggles manual input, and sees no visible "Select a voice", "Loading voices...", "Search voices...", "No voices found", "Add Voice ID Manually", "Enter voice ID", or "voices available" component-owned strings.
    Evidence: evidence/task-6-voice-selector-browser.txt and evidence/task-6-voice-selector.png

  Scenario: API voice metadata is preserved
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run src/components/__tests__/VoiceSelector.locale.test.tsx -t "does not translate API voice metadata" 2>&1 | tee ../evidence/task-6-voice-selector-metadata.txt
    Expected: Command exits 0 and proves fixture voice names/descriptions render exactly as returned.
    Evidence: evidence/task-6-voice-selector-metadata.txt
  ```

  Commit: YES | Message: `fix(ui): localize voice selector chrome` | Files: [`ui/src/components/VoiceSelector.tsx`, `ui/src/components/voice-selector/**`, `ui/src/lib/i18n/messages/voice.ts`, `ui/src/components/__tests__/VoiceSelector.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 7. Localize dictionary, template variables, and voicemail dialogs

  What to do: Add failing tests for the three smaller workflow dialogs. Localize visible titles, descriptions, labels, placeholders, button labels, timing/system-prompt helper text, and save/cancel copy. Keep the voicemail default system prompt as a technical editable prompt. Add Korean translations under a workflow-dialogs namespace.
  Must NOT do: Do not translate dictionary contents, context variable keys/values, `{{variable_name}}` syntax, LLM provider/model names, `CONVERSATION`/`VOICEMAIL` classifier outputs, or the default system prompt body.

  Parallelization: Can parallel: YES | Wave 2 | Blocks: [10] | Blocked by: [1, 2]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/DictionaryDialog.tsx:42-76` - dictionary modal visible copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/TemplateContextVariablesDialog.tsx:70-146` - template variables modal visible copy.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/VoicemailDetectionDialog.tsx:23-44` - system prompt contract to preserve.
  - Pattern:  `ui/src/app/workflow/[workflowId]/components/VoicemailDetectionDialog.tsx:111-201` - voicemail dialog visible copy.
  - API/Type: `ui/src/types/workflow-configurations.ts` - voicemail/workflow config shape imported at `VoicemailDetectionDialog.tsx:17-21`.
  - Test:     `ui/src/test/setup.ts` - render/test setup from Task 1.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/WorkflowDialogs.locale.test.tsx' 2>&1 | tee ../evidence/task-7-workflow-dialogs-green.txt` exits 0 after a red run is captured at `evidence/task-7-workflow-dialogs-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope workflow-dialogs 2>&1 | tee ../evidence/task-7-workflow-dialogs-audit.txt` exits 0.
  - [ ] Tests assert `DEFAULT_VOICEMAIL_SYSTEM_PROMPT` still contains English classifier examples and output tokens.
  - [ ] Tests assert saved dictionary/context variable values are unchanged after Korean render.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Workflow dialogs Korean mode
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@workflow-dialogs" 2>&1 | tee ../evidence/task-7-workflow-dialogs-browser.txt
    Expected: Browser opens dictionary, template variables, and voicemail dialogs in Korean mode and sees Korean labels while preserving prompt/code/value content.
    Evidence: evidence/task-7-workflow-dialogs-browser.txt and evidence/task-7-workflow-dialogs-*.png

  Scenario: Prompt and template syntax are preserved
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run 'src/app/workflow/[workflowId]/components/__tests__/WorkflowDialogs.locale.test.tsx' -t "preserves prompt and template syntax" 2>&1 | tee ../evidence/task-7-workflow-dialogs-edge.txt
    Expected: Command exits 0 and proves `{{variable_name}}`, `CONVERSATION`, and `VOICEMAIL` remain exact.
    Evidence: evidence/task-7-workflow-dialogs-edge.txt
  ```

  Commit: YES | Message: `fix(ui): localize workflow support dialogs` | Files: [`ui/src/app/workflow/[workflowId]/components/DictionaryDialog.tsx`, `ui/src/app/workflow/[workflowId]/components/TemplateContextVariablesDialog.tsx`, `ui/src/app/workflow/[workflowId]/components/VoicemailDetectionDialog.tsx`, `ui/src/lib/i18n/messages/workflowDialogs.ts`, `ui/src/app/workflow/[workflowId]/components/__tests__/WorkflowDialogs.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 8. Localize document upload and shared filter builder/controls

  What to do: Add failing tests for document upload idle, selected-file, upload-progress, validation-error, and OSS notice states. Add failing tests for filter builder card title/description/templates, attribute placeholder, active filters, clear/apply/auto-refresh, filter summaries, multi-select controls, and text-filter placeholders/errors. Localize component-owned UI text through `t()`. If `FilterBuilder.tsx` gains logic, split summary formatting and controls into smaller modules first. Keep file names, extensions, sizes, filter values, tag values, and backend field names unchanged.
  Must NOT do: Do not translate accepted file extensions, uploaded file names, retrieval mode enum values (`full_document`, `chunked`), database field names, filter operator values, keyboard shortcut symbols, or user-entered filter data.

  Parallelization: Can parallel: YES | Wave 2 | Blocks: [9, 10] | Blocked by: [1, 2]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/app/files/DocumentUpload.tsx:23-24` - file-size/type constants to preserve.
  - Pattern:  `ui/src/app/files/DocumentUpload.tsx:36-49` - OSS notice visible copy.
  - Pattern:  `ui/src/app/files/DocumentUpload.tsx:51-64` - file validation toasts.
  - Pattern:  `ui/src/app/files/DocumentUpload.tsx:103-142` - upload/process errors and success toast.
  - Pattern:  `ui/src/app/files/DocumentUpload.tsx:181-303` - selected-file, retrieval mode, drag/drop, progress, and choose-file UI.
  - Pattern:  `ui/src/components/filters/FilterBuilder.tsx:177-209` - summary strings.
  - Pattern:  `ui/src/components/filters/FilterBuilder.tsx:295-457` - filter builder visible UI.
  - Pattern:  `ui/src/components/filters/MultiSelectFilter.tsx:53-57` - selected-count summary.
  - Pattern:  `ui/src/components/filters/MultiSelectFilter.tsx:59-153` - multi-select labels/placeholders/errors.
  - Pattern:  `ui/src/components/filters/TextFilter.tsx:14-44` - default placeholder/error rendering.
  - API/Type: `ui/src/types/filters.ts:1-29` - attribute config and filter metadata.
  - API/Type: `ui/src/types/filters.ts:86-205` - filter template text and values that need localization without changing filter payloads.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run src/app/files/__tests__/DocumentUpload.locale.test.tsx src/components/filters/__tests__/FilterBuilder.locale.test.tsx 2>&1 | tee ../evidence/task-8-files-filters-green.txt` exits 0 after red evidence is captured at `evidence/task-8-files-filters-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope files,filters 2>&1 | tee ../evidence/task-8-files-filters-audit.txt` exits 0.
  - [ ] Tests assert invalid file type and oversize toasts are Korean while file extensions and file names remain exact.
  - [ ] Tests assert applying filters emits the same `ActiveFilter` payload in Korean and English.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Document upload and filters Korean mode
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@files-filters" 2>&1 | tee ../evidence/task-8-files-filters-browser.txt
    Expected: Browser opens mocked file upload and filter surfaces in Korean mode, exercises invalid upload and filter add/apply, and sees no visible "Drop your document here", "Choose File", "How should the agent use this document?", "Filter Workflow Runs", "Templates", "Select attribute to filter by", "Active Filters", "Clear All", or "Apply" component-owned strings.
    Evidence: evidence/task-8-files-filters-browser.txt and evidence/task-8-files-filters-*.png

  Scenario: Filter payloads and file values are stable
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run src/app/files/__tests__/DocumentUpload.locale.test.tsx src/components/filters/__tests__/FilterBuilder.locale.test.tsx -t "preserves values" 2>&1 | tee ../evidence/task-8-files-filters-values.txt
    Expected: Command exits 0 and proves file names/extensions, retrieval enum values, and filter payload values are unchanged.
    Evidence: evidence/task-8-files-filters-values.txt
  ```

  Commit: YES | Message: `fix(ui): localize upload and filter controls` | Files: [`ui/src/app/files/DocumentUpload.tsx`, `ui/src/components/filters/**`, `ui/src/types/filters.ts`, `ui/src/lib/i18n/messages/files.ts`, `ui/src/lib/i18n/messages/filters.ts`, `ui/src/app/files/__tests__/DocumentUpload.locale.test.tsx`, `ui/src/components/filters/__tests__/FilterBuilder.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 9. Localize superadmin runs page and superadmin-facing filter data

  What to do: After shared filter localization lands, add failing tests for superadmin runs page loading, empty state, page title/description, card title/description, table headers, refreshing state, tooltip headings, action button accessible names/titles, impersonation failure alert, unknown workflow fallback, pagination summary/buttons, and superadmin-specific filter labels/templates. Localize UI chrome while preserving raw workflow names, IDs, call disposition codes/tags, JSON tooltip payloads, trace URLs, dataset names, and timestamps unless locale formatting is explicitly introduced.
  Must NOT do: Do not translate Axiom/Langfuse URLs, dataset/project env var references, run IDs, workflow IDs, gathered context JSON, usage info JSON, disposition/tag data, or impersonation redirect behavior.

  Parallelization: Can parallel: NO | Wave 3 | Blocks: [10] | Blocked by: [1, 2, 8]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:251-258` - current date/duration helpers.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:265-280` - impersonation failure alert.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:284-340` - loading, title, description, empty state.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:348-380` - table headers.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:391-405` - workflow fallback and IDs.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:449-462` - tooltip headings.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:503-560` - trace links and open-workflow title.
  - Pattern:  `ui/src/app/superadmin/runs/page.tsx:571-620` - pagination copy.
  - Pattern:  `ui/src/components/filters/FilterBuilder.tsx:295-457` - localized shared filter UI from Task 8.
  - Pattern:  `ui/src/types/filters.ts:103-205` - filter template labels/descriptions to route through translation.
  - API/Type: `ui/src/lib/filterAttributes.ts` - workflow/superadmin filter attribute definitions if labels are sourced there.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run src/app/superadmin/runs/__tests__/SuperadminRuns.locale.test.tsx 2>&1 | tee ../evidence/task-9-superadmin-green.txt` exits 0 after a red run is captured at `evidence/task-9-superadmin-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --scope superadmin-runs 2>&1 | tee ../evidence/task-9-superadmin-audit.txt` exits 0.
  - [ ] Tests assert raw `gathered_context`, `usage_info`, disposition codes, tags, and trace URLs are not translated.
  - [ ] Tests assert pagination summary and previous/next buttons are Korean.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Superadmin runs Korean mode
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome --grep "@superadmin-runs" 2>&1 | tee ../evidence/task-9-superadmin-browser.txt
    Expected: Browser opens mocked superadmin runs page in Korean mode, exercises empty and populated states, and sees no visible "Loading workflow runs...", "Workflow Runs", "View and manage all workflow runs across organizations", "All Workflow Runs", "No workflow runs found.", "Refreshing...", "Previous", or "Next" component-owned strings.
    Evidence: evidence/task-9-superadmin-browser.txt and evidence/task-9-superadmin-*.png

  Scenario: Operational raw data remains exact
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run src/app/superadmin/runs/__tests__/SuperadminRuns.locale.test.tsx -t "preserves raw run data and trace URLs" 2>&1 | tee ../evidence/task-9-superadmin-raw-data.txt
    Expected: Command exits 0 and proves workflow names, tags, JSON payloads, trace URLs, and dataset env references remain exact.
    Evidence: evidence/task-9-superadmin-raw-data.txt
  ```

  Commit: YES | Message: `fix(ui): localize superadmin run management` | Files: [`ui/src/app/superadmin/runs/page.tsx`, `ui/src/app/superadmin/runs/components/**`, `ui/src/lib/filterAttributes.ts`, `ui/src/types/filters.ts`, `ui/src/lib/i18n/messages/superadmin.ts`, `ui/src/app/superadmin/runs/__tests__/SuperadminRuns.locale.test.tsx`, `ui/e2e/locale-korean.spec.ts`]

- [ ] 10. Tighten DOM overrides, html language behavior, full audit, and browser QA coverage

  What to do: Review everything fixed in Tasks 3-9 and remove or narrow Korean DOM override entries that now duplicate React-owned translations. Add tests proving `applyKoreanDomOverrides()` still translates allowed runtime/generated exact strings, skips `code`, `pre`, `textarea`, `input`, and `select`, translates text attributes, and disconnects the observer. Add or update browser QA so the Korean mode path sets `localStorage.ui_language='ko'`, mocks persisted user config to Korean, verifies `<html lang="ko">`, navigates across all target surfaces, captures screenshots, and runs the static audit. Keep any remaining English in Korean mode documented as allowlisted technical/raw data with reasons.
  Must NOT do: Do not remove DOM overrides needed for generated/runtime text that has no React translation owner. Do not mutate code/pre/textarea/input/select contents. Do not declare completion if the static audit has unexplained high-confidence findings.

  Parallelization: Can parallel: NO | Wave 3 | Blocks: [final verification] | Blocked by: [3, 4, 5, 6, 7, 8, 9]

  References (executor has NO interview context - be exhaustive):
  - Pattern:  `ui/src/lib/ko-dom-overrides.ts:1-24` - override table to narrow.
  - Pattern:  `ui/src/lib/ko-dom-overrides.ts:526-532` - text attributes translated by DOM overrides.
  - Pattern:  `ui/src/lib/ko-dom-overrides.ts:534-537` - skipped node contexts that must remain protected.
  - Pattern:  `ui/src/lib/ko-dom-overrides.ts:540-565` - exact-match text/attribute replacement.
  - Pattern:  `ui/src/lib/ko-dom-overrides.ts:582-617` - observer lifecycle.
  - Pattern:  `ui/src/context/LocaleContext.tsx:77-84` - `<html lang>` and DOM override activation.
  - Pattern:  `ui/src/app/layout.tsx:42-44` - server-rendered `<html lang="en" suppressHydrationWarning>`, which must be checked after client hydration.
  - Pattern:  `ui/src/lib/apiClient.ts:5-13` - browser API base URL uses `window.location.origin`, enabling Playwright route mocks against the local app.
  - Pattern:  `ui/src/app/api/auth/session/route.ts:7-32` - test can set local auth cookie without UI login.
  - Pattern:  `ui/src/app/api/auth/oss/route.ts:14-35` - local auth reads the session cookie.
  - External: `https://playwright.dev/docs/screenshots` - screenshot evidence capture.
  - External: `https://playwright.dev/docs/test-assertions` - auto-retrying visible text and attribute assertions.

  Acceptance criteria (agent-executable only):
  - [ ] `cd ui && npm run test:i18n -- --run src/lib/__tests__/ko-dom-overrides.test.ts src/context/__tests__/LocaleContext.test.tsx 2>&1 | tee ../evidence/task-10-dom-locale-green.txt` exits 0 after a red run is captured at `evidence/task-10-dom-locale-red.txt`.
  - [ ] `cd ui && npm run test:locale-audit -- --format=json --fail-on=high 2>&1 | tee ../evidence/task-10-full-audit.json` exits 0 and contains no unexplained high-confidence English UI findings.
  - [ ] `cd ui && npm run test:e2e:locale -- --project=chrome 2>&1 | tee ../evidence/task-10-full-browser.txt` exits 0 and screenshots are written for every target surface.
  - [ ] `cd ui && npm run build 2>&1 | tee ../evidence/task-10-build.txt` exits 0.
  - [ ] `git diff --check 2>&1 | tee evidence/task-10-diff-check.txt` exits 0.

  QA scenarios (MANDATORY - task incomplete without these):
  ```
  Scenario: Full Korean locale browser walk
    Tool:     playwright(real Chrome)
    Steps:    cd ui && npm run test:e2e:locale -- --project=chrome 2>&1 | tee ../evidence/task-10-full-browser.txt
    Expected: Browser sets authenticated local session and Korean preference, verifies `<html lang="ko">`, opens every target surface, captures screenshots, and finds no unallowlisted visible English UI text for the scoped surfaces.
    Evidence: evidence/task-10-full-browser.txt and evidence/task-10-*.png

  Scenario: DOM overrides only patch allowed exact runtime strings
    Tool:     bash
    Steps:    cd ui && npm run test:i18n -- --run src/lib/__tests__/ko-dom-overrides.test.ts -t "patches allowed text and skips code/input contexts" 2>&1 | tee ../evidence/task-10-dom-overrides-edge.txt
    Expected: Command exits 0 and proves exact text/attribute overrides work, code/pre/textarea/input/select contents remain unchanged, and observer cleanup disconnects.
    Evidence: evidence/task-10-dom-overrides-edge.txt
  ```

  Commit: YES | Message: `fix(ui): enforce Korean locale fallback coverage` | Files: [`ui/src/lib/ko-dom-overrides.ts`, `ui/src/context/LocaleContext.tsx`, `ui/src/lib/__tests__/ko-dom-overrides.test.ts`, `ui/src/context/__tests__/LocaleContext.test.tsx`, `ui/e2e/locale-korean.spec.ts`, `ui/scripts/audit-locale-fallback.mts`, `ui/src/lib/i18n/messages/**`]

## Final verification wave (MANDATORY - after all implementation tasks)
> Runs in PARALLEL. ALL must APPROVE. Surface results to the caller and wait for an explicit "okay" before declaring complete.
- [ ] F1. Plan compliance audit - every task done, every acceptance criterion met
- [ ] F2. Code quality review - diagnostics clean, idioms match, no dead code
- [ ] F3. Real manual QA - every QA scenario executed with evidence captured
- [ ] F4. Scope fidelity - nothing extra shipped beyond Must-Have, nothing Must-NOT-Have introduced

## Commit strategy
- One logical change per commit. Conventional Commits (`<type>(<scope>): <subject>` body + footer).
- Atomic: every commit builds and passes tests on its own.
- No "WIP" / "fix typo squash later" commits on the final branch - clean up before merge.
- Reference the plan file path in the final commit footer: `Plan: plans/korean-locale-fallback-audit.md`.

## Success criteria
- All Must-Have shipped; all QA scenarios pass with captured evidence; F1-F4 approved; commit history clean.
