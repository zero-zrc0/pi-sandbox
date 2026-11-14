/**
 * Semantic prefix lengths for Bash session approval suggestions.
 *
 * The number is how many leading tokens keep the authorization meaning of a
 * command. Multi-word keys win over single-word keys; a value larger than the
 * actual token count is truncated to that count.
 */

export const SESSION_PREFIX_ARITY: Readonly<Record<string, number>> = Object.freeze({
  // Version control
  git: 2,
  hg: 2,
  svn: 2,
  // Node tooling
  npm: 2,
  npx: 2,
  pnpm: 2,
  yarn: 2,
  bun: 2,
  "npm run": 3,
  "npm exec": 3,
  "pnpm run": 3,
  "pnpm exec": 3,
  "pnpm dlx": 3,
  "yarn run": 3,
  "bun run": 3,
  "bun x": 3,
  "bun add": 2,
  // Other runtimes
  deno: 2,
  pip: 2,
  pip3: 2,
  uv: 2,
  cargo: 2,
  go: 2,
  bundle: 2,
  "deno run": 3,
  "deno task": 3,
  "deno compile": 3,
  "uv run": 3,
  "uv pip": 3,
  "go run": 3,
  "bundle exec": 3,
  // Containers and orchestration
  docker: 2,
  podman: 2,
  kubectl: 2,
  helm: 2,
  "docker compose": 3,
  "docker container": 3,
  "docker image": 3,
  "docker network": 3,
  "docker volume": 3,
  "podman compose": 3,
  // Cloud
  aws: 3,
  az: 3,
  gcloud: 3,
  gh: 2,
  fly: 2,
  vercel: 2,
  wrangler: 2,
  "gh pr": 3,
  "gh issue": 3,
  "gh repo": 3,
  // Build and infrastructure
  make: 1,
  bazel: 2,
  terraform: 2,
  tofu: 2,
  pulumi: 2,
  systemctl: 2,
  service: 2,
  brew: 2,
  apt: 2,
  "apt-get": 2,
  yum: 2,
  dnf: 2,
  // Files and text
  ls: 1,
  ll: 1,
  la: 1,
  cat: 1,
  less: 1,
  more: 1,
  head: 1,
  tail: 1,
  grep: 1,
  rg: 1,
  ag: 1,
  find: 1,
  touch: 1,
  mkdir: 1,
  rm: 1,
  cp: 1,
  mv: 1,
  ln: 1,
  chmod: 1,
  chown: 1,
  du: 1,
  df: 1,
  echo: 1,
  printf: 1,
  diff: 1,
  patch: 1,
  wc: 1,
  sort: 1,
  uniq: 1,
  awk: 1,
  sed: 1,
  tar: 1,
  zip: 1,
  unzip: 1,
  // Network and processes
  curl: 1,
  wget: 1,
  ssh: 1,
  scp: 1,
  rsync: 1,
  ping: 1,
  kill: 1,
  killall: 1,
  pkill: 1,
});

const MULTI_WORD_KEYS: readonly string[] = Object.keys(SESSION_PREFIX_ARITY)
  .filter((key) => key.includes(" "))
  .sort((left, right) => {
    const leftWords = left.split(" ").length;
    const rightWords = right.split(" ").length;
    return leftWords === rightWords ? right.length - left.length : rightWords - leftWords;
  });

/**
 * Number of leading tokens that carry the command's meaning. An unknown
 * command keeps only its first token; a value beyond the token count is
 * truncated.
 */
export function commandPrefixArity(tokens: readonly string[]): number {
  if (tokens.length === 0) return 1;
  const lowered = tokens.map((token) => token.toLowerCase());
  for (const key of MULTI_WORD_KEYS) {
    const words = key.split(" ");
    if (words.length > lowered.length) continue;
    if (words.every((word, index) => lowered[index] === word)) {
      return Math.min(SESSION_PREFIX_ARITY[key], tokens.length);
    }
  }
  const single = SESSION_PREFIX_ARITY[lowered[0]];
  return single === undefined ? 1 : Math.min(single, tokens.length);
}
