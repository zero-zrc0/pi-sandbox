import {
  createCodemodeExtension,
  type ExtensionAPI,
  type ExtensionFactory,
  type ToolDefinition,
} from "@earendil-works/pi-coding-agent";

const CODEMODE_TOOL_NAME = "codemode";

export interface ManagedCodemodeExtensionOptions {
  readonly execute: ToolDefinition["execute"];
  readonly registerTool?: (tool: ToolDefinition) => void;
}

export function createManagedCodemodeExtension(
  options: ManagedCodemodeExtensionOptions,
): ExtensionFactory {
  const codemodeFactory = createCodemodeExtension();

  return (api) => {
    let registrations = 0;
    const registerTool = options.registerTool ?? api.registerTool.bind(api);
    const adaptedApi = new Proxy(api, {
      get(target, property) {
        if (property === "registerTool") {
          return (tool: ToolDefinition) => {
            if (tool.name !== CODEMODE_TOOL_NAME) {
              return registerTool(tool);
            }
            if (registrations !== 0) {
              throw new Error("Pi Codemode factory registered more than one codemode tool");
            }

            registrations += 1;
            registerTool({ ...tool, execute: options.execute });
          };
        }

        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    codemodeFactory(adaptedApi);

    if (registrations !== 1) {
      throw new Error("Pi Codemode factory did not register exactly one codemode tool");
    }
  };
}
