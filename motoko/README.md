# identity-attributes

Verify Internet Identity attribute bundles in relying-party canisters.
Pairs with `@icp-sdk/auth` v7.

## Install

```toml
# mops.toml
[dependencies]
identity-attributes = "0.4.1"
core                = "2.5.0"
```

Set the canister's environment variables in `icp.yaml`:

```yaml
canisters:
  - name: backend
    settings:
      environment_variables:
        trusted_attribute_signers: "rdmx6-jaaaa-aaaaa-aaadq-cai"  # II backend principal (required)
        frontend_origins:          "https://your-app.icp0.io"     # allowed origins, comma-separated (required)
        trusted_sso_domains:       "dfinity.org"                  # comma-separated, optional (omit to reject all sso:* keys)
```

## Backend

Add the mixin to your `persistent actor` with `include`. It injects the
two sign-in methods the frontend calls and runs your `onVerified`
callback on each verified bundle. What the callback does is yours to
decide. The example below keeps a profile per principal.

```motoko
import IdentityAttributes "mo:identity-attributes";
import Map        "mo:core/Map";
import Principal  "mo:core/Principal";

persistent actor {
  type Profile = { name : ?Text; email : ?Text; sso : ?Text };

  let profiles = Map.empty<Principal, Profile>();

  include IdentityAttributes({
    onVerified = func(caller, attrs) {
      let profile : Profile = { name = attrs.name; email = attrs.email; sso = attrs.sso };
      profiles.add(caller, profile)
    };
  });

  public query func getProfile(caller : Principal) : async ?Profile {
    profiles.get(caller)
  };
};
```

## Frontend

Fetch a nonce, request the bundle, replay it wrapped in an
`AttributesIdentity`. Passing the nonce as a promise lets sign-in and the
attribute request run together, so the user sees a single II prompt.

```typescript
import { AuthClient }         from "@icp-sdk/auth/client";
import { AttributesIdentity } from "@icp-sdk/core/identity";
import { HttpAgent, Actor }   from "@icp-sdk/core/agent";
import { Principal }          from "@icp-sdk/core/principal";

const authClient = new AuthClient();

// Anonymous handle, used only to fetch the nonce.
const anonymousAgent = await HttpAgent.create();
const anonymousActor = Actor.createActor(idl, { agent: anonymousAgent, canisterId });

// Nonce, sign-in, and attributes run in parallel.
const noncePromise      = anonymousActor._internet_identity_sign_in_start();
const signInPromise     = authClient.signIn();
const attributesPromise = authClient.requestAttributes({
  keys:  ["name", "verified_email"], // see "Requesting keys" below
  nonce: noncePromise,
});

const identity   = await signInPromise;
const attributes = await attributesPromise;

// Wrap so the bundle travels as sender_info (signer is the trusted II canister).
const verifiedAgent = await HttpAgent.create({
  identity: new AttributesIdentity({
    inner:  identity,
    attributes,
    signer: { canisterId: Principal.fromText("rdmx6-jaaaa-aaaaa-aaadq-cai") },
  }),
});
const verifiedActor = Actor.createActor(idl, { agent: verifiedAgent, canisterId });

const result = await verifiedActor._internet_identity_sign_in_finish(); // #ok once onVerified has run
```

### Requesting keys

The `keys` array lists the II attribute keys to request. This library reads two of them:

- **name**: `name`, `openid:<provider>:name`, or `sso:<domain>:name`
- **email**: `verified_email`, `openid:<provider>:verified_email`, or `sso:<domain>:email`

Where:

- `<provider>` is `https://accounts.google.com`, `https://appleid.apple.com`, or `https://login.microsoftonline.com/{tid}/v2.0` (`{tid}` is literal).
- `<domain>` is one of `trusted_sso_domains`.

Use `scopedKeys` from `@icp-sdk/auth/client` to build the scoped key
forms. For example, scoping to Google:

```typescript
scopedKeys({ openIdProvider: "google", keys: ["name", "verified_email"] })
// returns ["openid:https://accounts.google.com:name",
//          "openid:https://accounts.google.com:verified_email"]
```

## API

```motoko
include IdentityAttributes({
  onVerified : (Principal, { name : ?Text; email : ?Text; sso : ?Text }) -> ()
});

// Injected on your actor:
_internet_identity_sign_in_start()  : async Blob
_internet_identity_sign_in_finish() : async Result<(), IdentityAttributesError>

type IdentityAttributesError = {
  #NoAttributes;
  #MalformedCandid;
  #MissingField                 : Text;
  #FrontendOriginsNotConfigured;
  #FrontendOriginMismatch       : { expected : [Text]; got : Text };
  #Stale                        : { ageNs : Nat };
  #UnknownNonce;
  #AmbiguousAttribute           : { field : Text; sources : [Text] };
  #UntrustedSsoSource           : { domain : Text };
  #MixedSsoSources              : { ssoKeys : [Text]; otherKeys : [Text] };
};
```

Your `onVerified` callback receives the caller and the resolved
`{ name; email; sso }`. The `sso` field is the matched domain when
name/email came from `sso:` keys, otherwise `null`.

Resolution rules:

- Each field resolves from at most one key. Two candidates returns `#AmbiguousAttribute`.
- A bundle may carry both non-SSO and SSO keys, but the two are never combined: a mixed bundle is rejected with `#MixedSsoSources`.
- An untrusted `sso:<domain>:*` key rejects the whole bundle with `#UntrustedSsoSource`.
- Non-SSO email comes from `verified_email`. SSO email comes from `sso:<domain>:email`.

## Compatibility

| `mo:identity-attributes` | `@icp-sdk/auth` |
|---|---|
| `^0.4` | `^7` |
| `^0.3` | `^7` |

## License

Apache-2.0.
