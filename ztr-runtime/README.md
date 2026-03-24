flowchart TD

A[Client / Agent] --> B[Runtime API tokens.py]

B --> C[Aegis Engine]
C --> D[RiskDNA Engine]
D --> E[Blast Radius Simulator]
E --> F[OPA Policy Engine]

F -->|allow| G[Runtime Enforcement]
F -->|deny| H[Policy Denied]

G --> I[JWT Issued]
G --> J[Session Stored]

C --> K[Redis: Aegis Signals]
D --> L[Redis: RiskDNA Metrics]
G --> M[Redis: Sessions]

N[Control Plane] --> O[Policy Publish]
O --> P[Redis: Policy Store]
P --> Q[Runtime Policy Verification]

style F fill:#1e3a8a,color:#fff
style G fill:#065f46,color:#fff
style H fill:#7f1d1d,color:#fff
style D fill:#92400e,color:#fff
