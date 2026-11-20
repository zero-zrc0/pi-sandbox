const file = process.env.FIXTURE_SELF_PID_FILE;
if (file) require("node:fs").writeFileSync(file, String(process.pid));
