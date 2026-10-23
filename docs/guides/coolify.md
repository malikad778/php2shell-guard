# Fixing PHP2Shell on Self-Hosted Coolify Instances

1. **Update Coolify to a Fixed Release**:
   - Ensure Coolify itself is at or above the fixed release for its line: `4.0.1`, `4.1.3`, `4.2.1`, `4.3.24`, or `4.4.7` (see Coolify's PHP Security Advisory 2026).
2. **CRITICAL: Updating Coolify Does Not Rebuild Your Deployed Apps**:
   - Updating or isolating the Coolify control plane container does **not** update or isolate the Laravel, WordPress, PHP, or Node.js application containers that Coolify deployed.
   - You must trigger a fresh **Redeploy (without cache)** for every PHP and Node.js application managed by Coolify so each container pulls a patched runtime image.
