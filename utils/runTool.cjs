function runTool(command, args, outputFile) {
  return new Promise((resolve) => {
    console.log(`[Tool] ${command} started`);

    const proc = spawn(command, args);

    let finished = false;

    const cleanup = () => {
      if (!finished) {
        finished = true;
        clearTimeout(timeout);
        resolve();
      }
    };

    const timeout = setTimeout(() => {
      if (!finished) {
        console.log(`[Tool] ${command} timeout`);
        proc.kill("SIGKILL");
        cleanup();
      }
    }, TOOL_TIMEOUT);

    proc.stdout.on("data", (data) => {
      fs.appendFileSync(outputFile, data.toString());
    });

    proc.on("close", () => {
      if (!finished) {
        console.log(`[Tool] ${command} finished`);
        cleanup();
      }
    });

    proc.on("error", () => {
      if (!finished) {
        console.log(`[Tool] ${command} failed`);
        cleanup();
      }
    });
  });
}
