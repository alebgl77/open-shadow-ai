// Disabled: Chromium detaches beyond the owned process group's cleanup boundary.
// Do not read operator inputs, launch a browser, or write a success witness.
process.stdout.write(JSON.stringify({ schema: 1, status: 'not_evaluated',
  reason: 'unsupported_browser_containment', exit_code: 2 }) + '\n');
process.exitCode = 2;
