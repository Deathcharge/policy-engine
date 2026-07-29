# Licensing guide

Samsarix Policy Engine 0.1.0 is source-available under the Business Source License 1.1
(`BUSL-1.1`). The exact terms in `LICENSE` control; this guide is a practical summary, not legal
advice or a replacement for the license.

## What the current parameters mean

- Copying, modification, redistribution, and non-production use are permitted by BUSL-1.1.
- The Additional Use Grant permits production use totaling no more than 1,000 policy evaluation
  requests per calendar month across all production deployments under the user's control.
- Production use above that grant requires an alternative commercial license from Samsarix LLC.
- The engine contains no telemetry or license enforcement. Users are responsible for determining
  and recording whether their production use remains within the grant.
- On June 16, 2027—or the fourth anniversary of the first public distribution of this specific
  version, if earlier—the licensed work converts to Apache License 2.0.
- BUSL-1.1 applies separately to each released version, so later versions may name a different
  Change Date or Additional Use Grant prospectively. Already released terms cannot be changed
  retroactively.
- BUSL-1.1 is not an Open Source license before the applicable conversion date.

## Commercial and support contacts

For alternative or higher-volume production licensing, email
[contact@samsarix.com](mailto:contact@samsarix.com). For product support, email
[support@samsarix.com](mailto:support@samsarix.com). Security reports follow the private process in
`SECURITY.md`.

## Maintainer checklist

Before each public release:

1. Confirm Samsarix LLC owns or has compatible rights to every included contribution.
2. Name the exact released versions in `Licensed Work`.
3. Confirm the Additional Use Grant, Change Date, and Change License with qualified counsel.
4. Keep the BUSL-1.1 body unchanged; customize only its parameters and Additional Use Grant.
5. Keep `pyproject.toml`, the wheel metadata, README, and this guide consistent with `LICENSE`.
6. Preserve the license in every wheel, source archive, original copy, and modified copy.

The repository does not include a separate commercial license agreement. Samsarix LLC must supply
that agreement directly when granting rights outside BUSL-1.1.
