// Inert fixture. A normal local build entry point; no environment access,
// network request, or dynamic evaluation. Never executed.
const fs = require('fs');
fs.writeFileSync('build-report.txt', 'inert build step completed\n');
console.log('inert build step completed');
