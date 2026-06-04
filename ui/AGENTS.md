# UI - Frontend Application

Next.js 15 frontend for Recova, currently built on Dograh's workflow-builder UI.
The shell metadata says Recova, while many labels, screenshots, docs links, and
mental models still come from Dograh. New product-facing UI should use Recova
unless it is intentionally preserving an upstream or compatibility name.

## Project Structure

```
ui/
├── src/
│   ├── app/          # Next.js App Router pages
│   ├── components/   # React components
│   ├── lib/          # Utilities and configurations
│   ├── client/       # Auto-generated API client
│   ├── context/      # React context providers
│   ├── hooks/        # Custom React hooks
│   ├── constants/    # Application constants
│   └── types/        # TypeScript type definitions
├── public/           # Static assets
└── package.json
```

## Where to Find Things

| Looking for...      | Go to...                                             |
| ------------------- | ---------------------------------------------------- |
| Pages/routes        | `src/app/` - Next.js App Router (file-based routing) |
| Reusable components | `src/components/` - organized by feature             |
| Base UI primitives  | `src/components/ui/` - shadcn/ui components          |
| Workflow builder    | `src/components/flow/` - React Flow based            |
| API calls           | `src/client/` - auto-generated from OpenAPI spec     |
| Auth utilities      | `src/lib/auth/`                                      |
| Helper functions    | `src/lib/utils.ts`                                   |
| Global state        | `src/context/` - React context providers             |

## Tech Stack

- Next.js 15 with App Router, React 19, TypeScript
- Tailwind CSS with shadcn/ui components
- Zustand for state management
- @xyflow/react for workflow builder

## Recova UI Priorities

- Design for Korean B2B operators who repeatedly manage campaigns, workflows,
  recordings, reports, usage, API keys, and telephony configs. Favor dense,
  scan-friendly operational screens over marketing-style pages.
- The primary demo funnel is self-serve: prospects should create an agent,
  enter their own phone number, run a test call, and understand both inbound and
  outbound call value before adopting Recova at a company level. Keep onboarding,
  empty states, test-call flows, and telephony setup optimized for this path.
- Do not introduce Recova branding into docs links, deployment copy, or support
  links unless the destination is actually Recova-ready.
- Keep auth, selected organization/team, and API-token readiness explicit before
  fetching tenant data.
- Campaigns, reports, usage, settings, telephony configurations, and superadmin
  are high-risk B2B surfaces. Check empty, loading, error, and permission states
  when editing them.

## API Client

The `src/client/` directory is auto-generated from the backend OpenAPI spec. Whenever you add a
new api route in backend, and wish to use it in the UI, generate the client using below command.

```bash
npm run generate-client
```

## Conventions

### File Uploads

Always use a hidden `<input type="file">` with a visible `<Button>` that triggers it via `fileInputRef.current?.click()`. Never use a visible `<Input type="file">` — the native file input styling is inconsistent and confusing. Show the selected filename next to or below the button.

### Authenticated API Calls

Components that make API calls must wait for auth to be ready before fetching. Use `useAuth()` and guard the `useEffect` with `authLoading` and `user`:

```tsx
const { user, loading: authLoading } = useAuth();
const hasFetched = useRef(false);

useEffect(() => {
  if (authLoading || !user || hasFetched.current) return;
  hasFetched.current = true;
  fetchData();
}, [authLoading, user]);
```

The auth interceptor (which attaches the Bearer token) is only registered once auth is fully loaded. Fetching before that sends unauthenticated requests that silently fail.

## Development

```bash
npm install
npm run dev    # Runs on port 3000
```
