# 6. GRC Risk Assessment

**Type:** Hands-on portfolio project
**Tools:** Risk assessment, security controls, compliance mapping, remediation planning
**Companion repository:** [yankee256/cybersecurity-GRC-portfolio](https://github.com/yankee256/cybersecurity-GRC-portfolio)

## Objective

Show how governance, risk, and compliance work connects to technical security: identify a risk, assess it honestly, map it to a control and a framework, and plan a remediation that a business can actually implement.

This project links to the dedicated GRC portfolio repository, rather than duplicating it here, so employers can see both the breadth of this portfolio and the depth of the GRC work.

## Method

1. **Identify the asset and the risk**
   - What data or system is at risk? What threat could affect it?
2. **Assess likelihood and impact**
   - Use a simple, consistent scale (for example, Low / Medium / High for each).
   - Risk = likelihood × impact, with a written justification — not just a number.
3. **Map to controls and frameworks**
   - Which control addresses this risk? (For example, NIST Cybersecurity Framework, ISO 27001, CIS Controls)
   - Is the control implemented, partially implemented, or missing?
4. **Plan remediation**
   - Specific action, owner, and timeframe — not "improve security."
   - What residual risk remains after remediation?
5. **Track it**
   - Re-assess after remediation and record whether the risk actually went down.

## Sample risk register row

| Risk | Asset | Likelihood | Impact | Rating | Control / Framework | Remediation | Residual risk |
|------|-------|------------|--------|--------|---------------------|--------------|---------------|
| Unauthorised access to sensitive data | Internal file share | Medium | High | High | Access control, least privilege — NIST CSF Protect, ISO 27001 Annex A 5.15 | Enforce role-based access, review access quarterly, enable MFA | Medium |

## What I learned

- GRC is not paperwork for its own sake. A risk register that nobody acts on is useless; a register with owners and dates gets fixed.
- Mapping to a framework helps a team speak the same language — and helps an auditor verify the work.
- Technical skills and governance skills reinforce each other: you cannot assess a control you do not understand, and you cannot fix a risk you have not measured.
