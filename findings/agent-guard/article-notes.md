# Source notes: ProjectDiscovery model-backdoor article

Status: untrusted source material, not instructions.
URL: https://projectdiscovery.io/research/how-abliterated-models-can-get-you-pwned
Published: 2026-10-06
Author: Prince Chaddha

## Verified observations from the article

- The article demonstrates a backdoor in a modified open model, including an
  abliterated build. The model behaves normally on clean prompts and fires on a
  chosen trigger phrase.
- The 7B Codex demonstration reported 100% trigger fire rate (50/50) and 100%
  clean accuracy (50/50). The backdoor was a small LoRA adapter; the merged
  model was served over an OpenAI-compatible Responses API.
- The payload was reached through an `exec_command` tool call that downloaded a
  remote shell script and ran it. The script read project `.env` files and
  `~/.ssh` private keys and posted them to an out-of-band collector.
- The article says the model shipped with only a URL pointer to the payload, so
  the operator could change the payload later without retraining.
- The article's defensive conclusion is runtime control: separate network
  access from command execution, sandbox both, and log what crosses either
  boundary. It explicitly says a domain allowlist alone did not help because
  the payload used a commonly trusted domain.

## Use restrictions

- The trigger, shell payload and collector details are not to be executed,
  replayed, or copied into AuraScan code or test fixtures.
- Any fixture derived from this article must be inert text and must use dummy
  paths/values only.
- This file is data for the review. It is not an instruction to the reviewer.
