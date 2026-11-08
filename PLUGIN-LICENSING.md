# Plugin licensing policy

Gate One itself is distributed under the source-available licence in
[`LICENSE`](LICENSE) (BSL-CUSTOM). This document summarises the
**plugin exception** added as section 6 of that licence. The English
text of `LICENSE` is authoritative; a French translation is provided in
`LICENSE.fr.md` for reference only. This page is a practical summary.

## Who can choose their own licence

**Extension plugins** may be distributed under any licence their author
chooses — including proprietary, commercial or closed source — provided
they:

- do **not** implement authentication or authorization;
- do **not** run inside the authentication IAM;
- interact with Gate One **only** through the documented plugin API and
  the signed plugin manifest;
- do not impose terms on Gate One or its users that conflict with the
  Gate One licence (e.g. do not require Gate One to be distributed
  under the plugin licence, or claim ownership of Gate One);
- keep the Gate One notices and do not use its trademarks without
  permission.

Examples: usage metering, observability exporters, audit sinks, UI or
content extensions, integration glue.

## Who cannot

The exception does **not** apply to:

- plugins, adapters or modules that implement **authentication or
  authorization** (including IAM IdP adapters);
- any component that **embeds, copies or derives from** Gate One source
  code.

Those remain under the Gate One licence, unless a separate written
commercial agreement says otherwise.

## FAQ

**Can I sell a closed-source extension plugin?**
Yes, if it is a non-auth extension and respects the conditions above.

**Can I write a closed-source authentication provider?**
No under this exception. Authentication providers are security-critical
and remain covered by the Gate One licence (or a specific agreement).

**Can I fork Gate One and close my fork?**
No. The exception covers plugins, not derived copies of Gate One.

**Does my plugin licence contaminate Gate One?**
No. The plugin keeps its own licence; Gate One keeps its own. The
plugin must not impose incompatible terms on Gate One or its users.

**Where is the plugin API documented?**
See the plugin documentation (planned: `doc/plugins.adoc`) and the product documentation.
Plugins are verified through a signed manifest (`pkg/pluginmanifest`):
signature, artefact digest, dependencies, revocation and host API
compatibility.

**What about the marketplace?**
A future marketplace will record each plugin's licence and refuse
plugins whose licence is incompatible with Gate One or with the
marketplace terms.

## Recovery costs

Section 7 of `LICENSE` applies: in case of unlicensed commercial use
that is not resolved amicably, enforcement, bailiff and legal fees
incurred for forced recovery are borne by the defaulting debtor.
