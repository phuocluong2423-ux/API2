// API Extraction Engine — Shared Constants
// Referenced by background, inject, and content modules

export const AGE_VERSION = '1.0.0';

// PostMessage channel handshake types
export const MSG_INIT          = 'AGE_INIT';
export const MSG_INIT_ACK      = 'AGE_INIT_ACK';
export const MSG_CAPTURE       = 'CAPTURE';
export const MSG_ANALYSIS      = 'ANALYSIS_RESULT';
export const MSG_STORAGE_SCAN  = 'STORAGE_SCAN';
export const MSG_NAVIGATION    = 'AGE_NAVIGATION';
export const MSG_TRIGGER_SCAN  = 'AGE_TRIGGER_STORAGE_SCAN';
export const MSG_RESPONSE      = 'AGE_RESPONSE';

// Storage limits
export const HOT_BUFFER_MAX     = 2000;
export const BODY_TRUNCATE_BYTES = 20480; // 20 KB
export const WS_FRAME_MAX       = 50;
export const SSE_EVENT_MAX      = 100;
export const REPLAY_LOG_MAX     = 500;
export const ENDPOINT_CAP       = 2000;
export const GRAPHQL_OP_CAP     = 500;

// Prober defaults
export const PROBER_DELAY_MS    = 250;
export const PROBER_TIMEOUT_MS  = 5000;

// Discovery paths probed on every origin
export const DISCOVERY_PATHS = [
  '/swagger.json',
  '/openapi.json',
  '/api-docs',
  '/v2/api-docs',
  '/v3/api-docs',
  '/.well-known/openapi.json',
  '/graphql',
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/security.txt',
  '/api/swagger.json',
  '/api/openapi.json',
  '/api/v1/swagger.json',
  '/api/v2/swagger.json',
  '/api/v3/swagger.json',
  '/_api/swagger',
  '/docs/api.json',
  '/schema',
  '/graphiql',
  '/playground',
  '/altair',
  '/api-explorer',
];

// Paths that look destructive — skipped unless aggressiveMode=true
export const DESTRUCTIVE_PATTERNS = [
  /\/delete\b/i,
  /\/destroy\b/i,
  /\/remove\b/i,
  /\/drop\b/i,
  /\/truncate\b/i,
  /\/purge\b/i,
  /\/reset\b/i,
  /\/wipe\b/i,
  /\/nuke\b/i,
];

// Header/param key patterns that indicate credential material
export const CREDENTIAL_KEY_RE = /key|token|secret|sig(?:nature)?|auth|access|client_id|apikey|api_key|client_secret|bearer|credential|passwd|password/i;

// Headers that should NOT be replayed verbatim
export const SKIP_REPLAY_HEADERS = new Set([
  'host', 'content-length', 'transfer-encoding', 'connection',
  'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailers', 'upgrade',
]);

// Headers that identify the client — stripped in anon mode
export const ANON_STRIP_HEADERS = new Set([
  'referer', 'origin', 'sec-fetch-site', 'sec-fetch-mode',
  'sec-fetch-dest', 'sec-fetch-user', 'user-agent',
  'cookie', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
]);

// Window globals that commonly hold app state / API config
export const STATE_GLOBALS = [
  '__NEXT_DATA__', '__NUXT__', '__APOLLO_STATE__', '__REDUX_STATE__',
  '__INITIAL_STATE__', '__PRELOADED_STATE__', '__APP_STATE__', '__STORE__',
  '__ENV__', 'ENV', '_env', 'CONFIG', '__config', '__settings',
  '__REACT_QUERY_STATE__', '__SWR_CACHE__', 'appConfig', 'apiConfig',
];

// Cloud-provider credential patterns (regex source strings)
export const CLOUD_CRED_PATTERNS = {
  AWS_ACCESS_KEY:  'AKIA[0-9A-Z]{16}',
  GCP_API_KEY:     'AIza[0-9A-Za-z\\-_]{35}',
  GCP_OAUTH_TOKEN: 'ya29\\.[0-9A-Za-z\\-_]{60,}',
  AZURE_SAS_TOKEN: 'sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&',
  SLACK_TOKEN:     'xox[baprs]-[0-9A-Za-z\\-]{10,}',
  GITHUB_TOKEN:    'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}',
  STRIPE_KEY:      '(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,}',
  SENDGRID_KEY:    'SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}',
};

// Full GraphQL introspection query
export const GRAPHQL_INTROSPECTION = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name description locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name description isDeprecated deprecationReason
  }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType {
    kind name ofType { kind name ofType { kind name ofType { kind name } } }
  } } } }
}`;

// Lightweight type-enumeration query (fallback when full introspection is blocked)
export const GRAPHQL_TYPE_ENUM = '{ __schema { types { name kind } } }';
