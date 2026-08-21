/**
 * @jest-environment-options {"customExportConditions": ["react-server", "node", "node-addons"]}
 */

/**
 * CVE-2025-55182 lives inside React's Flight deserializer, not in this
 * codebase, so there is no vulnerable route of our own to exercise. This suite
 * is the canary in its place: it drives the deserializer Next actually ships
 * and asserts that the two prototype-chain lookups the exploit chains together
 * are still unguarded.
 *
 *   1. `bundlerConfig[id]`            — resolves a module id off the manifest
 *   2. `moduleExports[metadata[2]]`   — resolves an export name off that module
 *
 * Both take a client-controlled key and walk the prototype chain, which is what
 * hands the exploit `Function` and, from there, code execution. The probes below
 * stop one hop short of that: the reference they resolve is an inert `Object`
 * constructor and is never called. Upgrading React — or upgrading Next to a
 * release bundling a patched React — makes those lookups miss and fails here.
 */

type ServerReference = ((...args: unknown[]) => unknown) | null;

type ServerManifest = Record<
  string,
  { id: string; chunks: string[]; name: string }
>;

interface FlightServer {
  decodeAction(
    body: FormData,
    serverManifest: ServerManifest
  ): Promise<ServerReference>;
}

const FLIGHT_SERVERS = {
  webpack:
    "next/dist/compiled/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.production.js",
  turbopack:
    "next/dist/compiled/react-server-dom-turbopack/cjs/react-server-dom-turbopack-server.node.production.js",
} as const;

const STUB_MODULE_ID = "stub-module";
const DECLARED_EXPORT = "declaredAction";
const INHERITED_PROPERTY = "constructor";
const UNDECLARED_MODULE_ID = "no-such-module";
const MANIFEST_MISS = /in the React Server Manifest/;

const MANIFEST: ServerManifest = {
  [STUB_MODULE_ID]: { id: STUB_MODULE_ID, chunks: [], name: DECLARED_EXPORT },
};

beforeAll(() => {
  (
    globalThis as unknown as { __next_require__: (id: string) => unknown }
  ).__next_require__ = () => ({
    [DECLARED_EXPORT]: function declaredAction() {},
  });
});

/**
 * Feeds the deserializer the `$ACTION_ID_<id>` field a Server Action request
 * carries, with `id` fully client-controlled — exactly what React2Shell abuses.
 * `async` so that a synchronous throw inside `decodeAction` surfaces as a
 * rejection like any other failure.
 */
async function decodeActionReference(
  flight: FlightServer,
  referenceId: string
): Promise<ServerReference> {
  const body = new FormData();
  body.append(`$ACTION_ID_${referenceId}`, "1");
  return flight.decodeAction(body, MANIFEST);
}

async function rejectionMessage(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe.each(Object.entries(FLIGHT_SERVERS))(
  "React 19 RCE (CVE-2025-55182) – %s Flight deserializer",
  (_bundler, modulePath) => {
    const flight = require(modulePath) as FlightServer;

    it("resolves a reference the manifest declares", async () => {
      const action = await decodeActionReference(
        flight,
        `${STUB_MODULE_ID}#${DECLARED_EXPORT}`
      );

      expect(action).toBeInstanceOf(Function);
      expect(action!.name).toBe(`bound ${DECLARED_EXPORT}`);
    });

    it("rejects a module id the manifest does not declare", async () => {
      await expect(
        decodeActionReference(flight, UNDECLARED_MODULE_ID)
      ).rejects.toThrow(MANIFEST_MISS);
    });

    it("resolves an inherited property as a module id", async () => {
      const message = await rejectionMessage(
        decodeActionReference(flight, INHERITED_PROPERTY)
      );

      expect(message).not.toMatch(MANIFEST_MISS);
    });

    it("resolves an inherited property as an export name", async () => {
      const action = await decodeActionReference(
        flight,
        `${STUB_MODULE_ID}#${INHERITED_PROPERTY}`
      );

      expect(action).toBeInstanceOf(Function);
      expect(action!.name).toBe(`bound ${Object.name}`);
    });
  }
);
