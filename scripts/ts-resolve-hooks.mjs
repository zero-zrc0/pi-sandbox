/**
 * Minimal ESM resolver for the schema script.
 *
 * The production modules use TypeScript's extensionless relative imports and
 * the package `#approve-core`/`#sandbox`/`#config` maps, which `node --experimental-strip-types` does not
 * resolve on its own. Node already strips the types; this hook only retries a
 * failed lookup with a `.ts` suffix.
 */
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (error) {
    if (error?.code !== "ERR_MODULE_NOT_FOUND") throw error;
    if (!specifier.startsWith(".") && !specifier.startsWith("#")) throw error;
    return nextResolve(`${specifier}.ts`, context);
  }
}
