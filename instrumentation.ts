export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./instrumentation.node");
    const { assertDatabaseIsCurrent } = await import("./lib/schema-guard");

    try {
      await assertDatabaseIsCurrent();
    } catch (error) {
      // A rejected register() leaves Next listening and answering every request
      // with a bare 500, so the process has to end for the reason to be read.
      // console.error is asynchronous on a pipe, which is what stderr is under
      // `docker logs`, and process.exit drops whatever has not flushed.
      const { writeSync } = await import("fs");
      writeSync(2, `${error instanceof Error ? error.message : error}\n`);
      process.exit(1);
    }
  }
}
