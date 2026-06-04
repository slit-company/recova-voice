import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_ROOT = resolve(__dirname, "..");
const SRC_ROOT = resolve(UI_ROOT, "src");
const KO_OVERRIDES_PATH = resolve(SRC_ROOT, "lib/ko-dom-overrides.ts");

const SCAN_ROOTS = [
    resolve(SRC_ROOT, "app"),
    resolve(SRC_ROOT, "components"),
];

const VISIBLE_ATTRS = new Set([
    "aria-description",
    "aria-label",
    "alt",
    "placeholder",
    "title",
]);

const SKIP_DIRS = new Set([
    ".next",
    "node_modules",
    "client",
]);

const TECHNICAL_TERMS = [
    "API",
    "CSV",
    "DTMF",
    "HTTP",
    "HTTPS",
    "JSON",
    "JWT",
    "LLM",
    "MCP",
    "POST",
    "SIP",
    "STT",
    "TTS",
    "URL",
    "UUID",
    "WebRTC",
    "Recova",
    "Dograh",
    "Twilio",
    "ElevenLabs",
    "Deepgram",
    "Azure",
    "Google",
    "OpenAI",
    "Anthropic",
    "Groq",
    "Langfuse",
    "Sentry",
    "PostHog",
    "Slack",
    "GitHub",
    "Next.js",
    "React",
    "Bearer",
    "Basic Auth",
    "OAuth",
    "ISO",
    "ISO-2",
    "MinIO",
    "PostgreSQL",
    "Redis",
];

interface Finding {
    file: string;
    line: number;
    kind: string;
    text: string;
}

function walk(dir: string): string[] {
    const entries = readdirSync(dir, { withFileTypes: true });
    const files: string[] = [];
    for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
            if (!SKIP_DIRS.has(entry.name)) {
                files.push(...walk(fullPath));
            }
            continue;
        }
        if (entry.isFile() && extname(entry.name) === ".tsx") {
            files.push(fullPath);
        }
    }
    return files;
}

function unescapeString(value: string): string {
    return value
        .replaceAll("\\`", "`")
        .replaceAll('\\"', '"')
        .replaceAll("\\'", "'")
        .replaceAll("\\n", "\n")
        .replaceAll("\\t", "\t");
}

function extractQuotedStrings(source: string): Set<string> {
    const values = new Set<string>();
    const stringPattern = /(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/g;
    for (const match of source.matchAll(stringPattern)) {
        const raw = match[2];
        if (raw !== undefined) {
            values.add(normalizeText(unescapeString(raw)));
        }
    }
    return values;
}

function normalizeText(value: string): string {
    return value.replace(/\s+/g, " ").trim();
}

function lineNumberAt(source: string, index: number): number {
    let line = 1;
    for (let i = 0; i < index; i++) {
        if (source.charCodeAt(i) === 10) {
            line++;
        }
    }
    return line;
}

function decodeJsxEntities(value: string): string {
    return value
        .replace(/&nbsp;/g, " ")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&ldquo;/g, "\"")
        .replace(/&rdquo;/g, "\"")
        .replace(/&mdash;/g, "-")
        .replace(/&#39;/g, "'");
}

function hasEnglishLetters(value: string): boolean {
    return /[A-Za-z]/.test(value);
}

function isTechnicalOrExample(value: string): boolean {
    const text = normalizeText(value);
    if (text.length === 0) {
        return true;
    }
    if (!hasEnglishLetters(text)) {
        return true;
    }
    if (/[가-힣]/.test(text)) {
        return true;
    }
    if (/^(a|an|and|or|the|to|in|of|for|by|as|on|use|no)$/i.test(text)) {
        return true;
    }
    if (/^[-+*/=<>()[\]{}.,:;'"`|\\\d\s]+$/.test(text)) {
        return true;
    }
    if (
        /(^|\s|\[)(bg|text|border|ring|shadow|rounded|flex|grid|absolute|relative|opacity|cursor|hover|focus|data-|aria-|group|peer|w|h|min|max|px|py|p|m|gap|items|justify|transition|select|animate|dark|md|lg|xl)-/.test(text) ||
        /(var\(|rgba?\(|hsl\(|calc\(|\d+(px|rem|vh|vw|ms)|ease|data-radix)/.test(text)
    ) {
        return true;
    }
    if (/^_blank$|^use client$|^en-US$|^N\/A$/.test(text)) {
        return true;
    }
    if (/^(Enter|Escape|Backspace|Ctrl)$/.test(text)) {
        return true;
    }
    if (/^[A-Z]{3} dd, yyyy$/.test(text)) {
        return true;
    }
    if (/^(true|false|null|undefined)$/i.test(text)) {
        return true;
    }
    if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(text)) {
        return true;
    }
    if (/^(sm|md|lg|xl|2xl|xs|left|right|top|bottom|center)$/.test(text)) {
        return true;
    }
    if (/^[a-z0-9_.-]+@[a-z0-9_.-]+\.[a-z]{2,}$/i.test(text)) {
        return true;
    }
    if (/^(https?:\/\/|wss?:\/\/|\/|#)/i.test(text)) {
        return true;
    }
    if (/[{}]/.test(text) || text.includes("{{") || text.includes("}}")) {
        return true;
    }
    if (/^[a-z][a-z0-9_.-]*$/.test(text) && text.length < 32) {
        return true;
    }
    if (/^[a-z]+[A-Z][A-Za-z0-9]*$/.test(text)) {
        return true;
    }
    if (/^[A-Z0-9_.-]+$/.test(text) && text.length < 24) {
        return true;
    }
    if (/^[A-Z][a-zA-Z0-9_.-]+$/.test(text) && TECHNICAL_TERMS.includes(text)) {
        return true;
    }
    if (TECHNICAL_TERMS.some((term) => text === term)) {
        return true;
    }
    if (/^e\.g\.,/i.test(text)) {
        return true;
    }
    if (/^e\.g\./i.test(text)) {
        return true;
    }
    if (/\be\.g\./i.test(text)) {
        return true;
    }
    if (/^Example/i.test(text) && /[:{]/.test(text)) {
        return true;
    }
    if (/\b(window\.|\.start\(\)|\.end\(\)|onCallStart|onCallEnd|onStatusChange|onError|script tag|div with id=|JS API|HTML)\b/.test(text)) {
        return true;
    }
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$/.test(text)) {
        return true;
    }
    return false;
}

function splitVisibleText(value: string): string[] {
    return decodeJsxEntities(value)
        .split(/\s{2,}|\n+/)
        .map(normalizeText)
        .filter((text) => text.length > 0);
}

function isCovered(text: string, coveredEnglish: Set<string>): boolean {
    if (coveredEnglish.has(text)) {
        return true;
    }
    const withoutTrailingPunctuation = text.replace(/[.:;!?]+$/, "");
    if (coveredEnglish.has(withoutTrailingPunctuation)) {
        return true;
    }
    for (const source of coveredEnglish) {
        if (shouldCoverTextFragment(source) && text.includes(source)) {
            return true;
        }
    }
    return false;
}

function shouldCoverTextFragment(source: string): boolean {
    return (
        source.length >= 8 ||
        /[:.!?)]$/.test(source) ||
        source === "Show" ||
        source === "Hide" ||
        source === "Never"
    );
}

function collectCoverageStrings(): Set<string> {
    const coverage = new Set<string>();
    const source = readFileSync(KO_OVERRIDES_PATH, "utf-8");
    for (const value of extractQuotedStrings(source)) {
        if (hasEnglishLetters(value)) {
            coverage.add(value);
        }
    }
    return coverage;
}

function scanFile(path: string, coveredEnglish: Set<string>): Finding[] {
    const source = readFileSync(path, "utf-8");
    const sourceFile = ts.createSourceFile(
        path,
        source,
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX,
    );
    const findings: Finding[] = [];
    const relPath = relative(UI_ROOT, path);

    function addFinding(kind: string, text: string, position: number): void {
        if (isTechnicalOrExample(text) || isCovered(text, coveredEnglish)) {
            return;
        }
        findings.push({
            file: relPath,
            line: lineNumberAt(source, position),
            kind,
            text,
        });
    }

    function visit(node: ts.Node): void {
        if (ts.isJsxText(node)) {
            for (const text of splitVisibleText(node.getFullText(sourceFile))) {
                addFinding("jsx-text", text, node.getStart(sourceFile));
            }
        }

        if (ts.isJsxAttribute(node) && VISIBLE_ATTRS.has(node.name.text)) {
            const initializer = node.initializer;
            if (initializer !== undefined && ts.isStringLiteral(initializer)) {
                addFinding(
                    node.name.text,
                    normalizeText(unescapeString(initializer.text)),
                    initializer.getStart(sourceFile),
                );
            }
        }

        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
            if (!isIgnoredStringLiteral(node)) {
                addFinding("string-literal", normalizeText(unescapeString(node.text)), node.getStart(sourceFile));
            }
        }

        ts.forEachChild(node, visit);
    }

    visit(sourceFile);
    return findings;
}

function isIgnoredStringLiteral(node: ts.StringLiteral | ts.NoSubstitutionTemplateLiteral): boolean {
    const parent = node.parent;
    let current: ts.Node | undefined = node.parent;
    let hasJsxExpressionAncestor = false;
    while (current) {
        if (
            ts.isJsxAttribute(current) &&
            (current.name.text === "className" || current.name.text === "class")
        ) {
            return true;
        }
        if (ts.isJsxExpression(current)) {
            hasJsxExpressionAncestor = true;
        }
        current = current.parent;
    }
    if (!hasJsxExpressionAncestor) {
        return true;
    }
    if (ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent)) {
        return true;
    }
    if (ts.isLiteralTypeNode(parent)) {
        return true;
    }
    if (ts.isPropertyAssignment(parent) && parent.name === node) {
        return true;
    }
    if (ts.isElementAccessExpression(parent)) {
        return true;
    }
    if (ts.isJsxAttribute(parent)) {
        return true;
    }
    return false;
}

const coveredEnglish = collectCoverageStrings();
const files = SCAN_ROOTS
    .filter((root) => statSync(root, { throwIfNoEntry: false })?.isDirectory())
    .flatMap(walk)
    .sort();

const findings = files.flatMap((file) => scanFile(file, coveredEnglish));

if (findings.length > 0) {
    console.error("Missing Korean UI coverage for visible English strings:\n");
    for (const finding of findings) {
        console.error(
            `${finding.file}:${finding.line} [${finding.kind}] ${JSON.stringify(finding.text)}`,
        );
    }
    console.error(
        `\n${findings.length} uncovered visible strings. Add a t(...) message or KO_DOM_TEXT_OVERRIDES entry, unless the string is a deliberate technical example.`,
    );
    process.exit(1);
}

console.log(
    `Korean UI coverage OK: ${files.length} files scanned, ${coveredEnglish.size} English source strings covered.`,
);
