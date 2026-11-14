/**
 * Sensitive-path references of one unit, projected for the responsibility chain
 * (v4 §2 priority 40, `sensitive-paths`).
 *
 * What it does: maps the directions a unit proves (`UnitAccessFact[]` from
 * `chain/facts.ts`) onto the protected path families and their surface, so the
 * chain handler can deny a write/delete and ask for a read. The handler decides;
 * this module only names targets.
 *
 * The protected families mirror the definitions the repo already has instead of
 * inventing a new policy:
 *
 * - control directories `.git`, `.agents`, `.codex`, `.aws`
 *   (`sandbox/path.ts` `PROTECTED_CONTROL_DIRECTORY_NAMES`);
 * - credential paths from `risk/danger.ts`'s `credential-upload` class:
 *   `SSH_KEY_PATHS` (`.ssh`, `id_rsa`/`id_ed25519`, ...), `AWS_CREDENTIAL_PATHS`
 *   (`.aws` directory), `DOTENV_PATHS` (`.env`, `.env.*`),
 *   `PRIVATE_KEY_FILES` (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`),
 *   `CLOUD_CREDENTIAL_FILES` (`.netrc`, `.git-credentials`, `.npmrc`,
 *   `.pypirc`, `.docker`, `.kube`) and `CLOUD_CREDENTIAL_DIRECTORIES`
 *   (`.config/gcloud`, `.config/gh`, `.azure`).
 *
 * What it does not do: no file system access, no reading of the command text,
 * no danger analysis (that is `risk/danger.ts`), no verdict. Direction is never
 * guessed: `network`, `unknown` and `review` facts have no proven target
 * direction and produce no reference, so the mode baseline's unknown state
 * stays in charge. Database data directories are deliberately not classified: no
 * existing pattern defines them (`risk/danger.ts` leaves that policy open) and
 * guessing directory names would flag ordinary repositories. A local delete
 * whose fact does not carry `externalDelete` is reported as `write`: the fact
 * vocabulary only marks external deletes, and both surfaces are mutating.
 */
import type { CallState } from "#approve-core/contracts";
import { pathFlavorForPlatform, type PathFlavor } from "#approve-core/utils/path/path-flavor";
import type { SensitiveRef, SensitiveSurface, UnitAccessFact } from "../facts";

export interface ProjectSensitiveFactsInput {
  readonly call: CallState;
  readonly access: readonly UnitAccessFact[];
  /** Base for relative fact paths; defaults to `process.cwd()`. */
  readonly cwd?: string;
  /** Path language for resolution and case folding; defaults to `process.platform`. */
  readonly platform?: NodeJS.Platform;
}

interface SensitiveFamily {
  readonly category: string;
  readonly patterns: readonly RegExp[];
}

const GIT_DIRECTORY = /(?:^|[\\/])\.git(?:[\\/]|$)/u;
const AGENT_CONTROL_DIRECTORIES = /(?:^|[\\/])\.(?:agents|codex)(?:[\\/]|$)/u;
const SSH_DIRECTORY = /(?:^|[\\/])\.ssh(?:[\\/]|$)/u;
const SSH_KEY_FILES = /(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/u;
const AWS_DIRECTORY = /(?:^|[\\/])\.aws(?:[\\/]|$)/u;
const DOTENV_PATHS = /(?:^|[\\/])\.env(?:\.|$)/u;
const PRIVATE_KEY_FILES = /\.(?:pem|key|p12|pfx|jks)$/u;
const CLOUD_CREDENTIAL_FILES =
  /(?:^|[\\/])\.(?:netrc|git-credentials|npmrc|pypirc|docker|kube)(?:[\\/]|$)/u;
const CLOUD_CREDENTIAL_DIRECTORIES =
  /(?:^|[\\/])\.config[\\/]+(?:gcloud|gh)(?:[\\/]|$)|(?:^|[\\/])\.azure(?:[\\/]|$)/u;

/**
 * Detection order: the first matching family names the category. Families do
 * not overlap in practice; the order only decides the label if one ever does.
 */
const SENSITIVE_PATH_FAMILIES: readonly SensitiveFamily[] = Object.freeze([
  { category: "git", patterns: [GIT_DIRECTORY] },
  { category: "agent-control", patterns: [AGENT_CONTROL_DIRECTORIES] },
  { category: "ssh", patterns: [SSH_DIRECTORY, SSH_KEY_FILES] },
  { category: "aws", patterns: [AWS_DIRECTORY] },
  { category: "dotenv", patterns: [DOTENV_PATHS] },
  { category: "private-key", patterns: [PRIVATE_KEY_FILES] },
  {
    category: "cloud-credentials",
    patterns: [CLOUD_CREDENTIAL_FILES, CLOUD_CREDENTIAL_DIRECTORIES],
  },
]);

function categoryOf(foldedPath: string): string | undefined {
  for (const family of SENSITIVE_PATH_FAMILIES) {
    if (family.patterns.some((pattern) => pattern.test(foldedPath))) return family.category;
  }
  return undefined;
}

/**
 * The protected family of one path, or `undefined` when it is not protected.
 * A test/audit seam for the projection; it resolves nothing and needs no cwd.
 */
export function sensitivePathCategory(
  path: string,
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  const trimmed = path.trim();
  if (trimmed.length === 0 || trimmed.includes("\0")) return undefined;
  const flavor = pathFlavorForPlatform(platform);
  return categoryOf(flavor.fold(flavor.normalize(trimmed)));
}

/** Direction a fact proves, or `undefined` when it proves no target direction. */
function surfaceOf(fact: UnitAccessFact): SensitiveSurface | undefined {
  if (fact.kind === "read") return "read";
  if (fact.kind === "write") return fact.externalDelete === true ? "delete" : "write";
  return undefined;
}

/**
 * A provider may report a direction without a path; the call's own `path`
 * argument is then the only target it froze. Using it can only add a reference
 * (tighten), never remove one, and shell calls have no `path` argument.
 */
function callPathArgument(call: CallState): string | undefined {
  const value = call.arguments.path;
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function resolvePath(path: string, flavor: PathFlavor, cwd: string): string | undefined {
  const trimmed = path.trim();
  if (trimmed.length === 0 || trimmed.includes("\0")) return undefined;
  const resolved = flavor.resolve(cwd, trimmed);
  return resolved.length === 0 ? undefined : resolved;
}

/**
 * Project one unit's access facts onto sensitive references.
 *
 * The same path may be referenced once per surface (a read plus a write is two
 * references, because the two directions are different evidence); repeated
 * identical `(path, surface)` pairs are collapsed. Order follows the fact order
 * so the result is deterministic for one frozen call.
 */
export function projectSensitiveFacts(
  input: ProjectSensitiveFactsInput,
): readonly SensitiveRef[] {
  const platform = input.platform ?? process.platform;
  const flavor = pathFlavorForPlatform(platform);
  const cwd = input.cwd ?? process.cwd();
  const fallbackPath = callPathArgument(input.call);
  const refs: SensitiveRef[] = [];
  const seen = new Set<string>();

  for (const fact of input.access) {
    const surface = surfaceOf(fact);
    if (surface === undefined) continue;
    const path = fact.path ?? fallbackPath;
    if (path === undefined) continue;
    const resolved = resolvePath(path, flavor, cwd);
    if (resolved === undefined) continue;
    const folded = flavor.fold(resolved);
    const category = categoryOf(folded);
    if (category === undefined) continue;
    const key = `${surface}\u0000${folded}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push(Object.freeze({ path: resolved, category, surface }));
  }

  return Object.freeze(refs);
}
