# Security

Threat Profile is designed for public-source intelligence and static hosting. The browser does not need API keys, accounts or a backend service.

Do not commit or publish:

- API keys, tokens or credentials;
- private intelligence reports or customer data;
- internal indicators, asset inventories or investigation notes;
- organisation names or technology context that is not approved for public disclosure.

Organisation names entered in the interface stay in the current browser page and are excluded from generated share links. Sector, country and technology terms may appear in the share URL, so review the URL before sending it.

If private sources are added later, collect them in a controlled workflow, keep credentials in repository or environment secrets, minimise the published fields, and complete a disclosure review before deployment.

Upstream data is treated as untrusted input. The refresh process parses and validates it, applies minimum coverage and regression guards, and the interface escapes values before rendering them. The generated site remains a public intelligence aid, not a safe place for sensitive case data.

Report a vulnerability privately to the repository owner. Do not open a public issue containing exploit details, credentials, sensitive URLs or customer information.
