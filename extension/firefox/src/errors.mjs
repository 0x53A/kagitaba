// Never forward library messages, URLs, response bodies, or request arguments.
// Only fixed diagnostics may cross the privileged UI boundary or enter logs.
const messages = new Set([
  'This entry changed or was deleted. Reopen it before saving; your draft has been kept.',
  'Unknown wallet participant', 'Invalid participant name',
  'No remote configured', 'Invalid remote credentials',
  'Unlock the wallet to remember the remote token',
  'Unlock the wallet to use the saved remote token',
  'Saved token belongs to a different remote username',
  'No saved remote token. Enter a token in connection settings',
  'Unlock Kagitaba first', 'Connect a wallet first',
  'This installation already has a connected wallet',
  'Use an HTTPS remote URL without credentials or query parameters',
  'Remote wallet branch is missing', 'Remote refused update', 'No remote configured',
  'Rollback or divergent history', 'Unauthorized or invalid commit signature',
  'Root is not enrolled', 'Explicit root trust is required',
  'Invalid transfer', 'Transfer digest mismatch', 'Object digest mismatch',
  'Unsigned or nonlinear history', 'Noncanonical commit headers',
  'Unsupported wallet history', 'Conflicting wallet changes',
  'Unsupported commit header', 'Invalid commit', 'Invalid header',
  'Duplicate signature', 'Invalid tree', 'Invalid parent', 'Invalid object ID',
  'Invalid object', 'Expected tree', 'Expected commit', 'Unsafe tree path',
  'Unsupported tree mode', 'Snapshot limit', 'History limit', 'Transfer limit',
  'Oversized commit', 'Tree nesting limit',
]);
const gitCodes = new Set(['InternalError','UnsafeFilepathError','ObjectTypeError','InvalidOidError','NoRefspecError','AlreadyExistsError','AmbiguousError','CommitNotFetchedError','GitPushError','InvalidFilepathError','InvalidRefNameError','MaxDepthError','MissingNameError','MissingParameterError','MultipleGitError','NoCommitError']);
function location(error) {
  // Retain only bundled source coordinates, never the message or full stack.
  const match = typeof error?.stack === 'string' && error.stack.match(/(?:moz-extension:\/\/[^\s/]+\/)?background\.js:(\d+):(\d+)/);
  return match ? ` [background.js:${match[1]}:${match[2]}]` : '';
}
export function safeDiagnostic(error) {
  if (messages.has(error?.message)) return error.message;
  const code = error?.code;
  if (code === 'HttpError') {
    const status = error?.data?.statusCode;
    if (status === 401 || status === 403) return 'Git server denied access. Check the username, token and repository permissions.';
    if (status === 404) return 'Git repository not found or hidden by missing permissions. Check the HTTPS URL and token.';
    return 'Git server returned an HTTP error.';
  }
  if (code === 'NotFoundError') return 'Required Git reference or object was not found. Check that the remote contains the wallet branch.';
  if (code === 'SmartHttpError') return 'The remote did not provide a supported smart Git HTTP response.';
  if (code === 'PushRejectedError') return 'Git push rejected. Fetch and review the remote history before retrying.';
  if (code === 'EmptyServerResponseError') return 'Git server returned an empty response. Check the repository URL.';
  if (code === 'ParseError') return 'The Git server response or Git data could not be parsed.';
  if (code === 'RemoteCapabilityError') return 'The Git server lacks a required protocol capability.';
  if (code === 'UrlParseError' || code === 'UnknownTransportError') return 'The Git remote URL is invalid or uses an unsupported transport.';
  if (code === 'UserCanceledError') return 'Git authentication was cancelled.';
  if (error?.name === 'QuotaExceededError') return 'Browser storage quota exceeded.';
  if (error?.name === 'NetworkError' || error?.message === 'NetworkError when attempting to fetch resource.') return 'Network request failed. Check connectivity, TLS certificates and extension host permissions.';
  const categories = ['TypeError', 'ReferenceError', 'SyntaxError', 'SecurityError', 'InvalidStateError', 'NotAllowedError', 'AbortError'];
  if (categories.includes(error?.name)) return `Browser operation failed (${error.name}). Inspect the extension debugger with pause on caught exceptions for the failing call.`;
  const category = gitCodes.has(code) ? code : 'unclassified error';
  return `Operation failed (${category})${location(error)}. Check unlock, permissions, trust and request state.`;
}

const stages = new Set(['fetch', 'verify', 'save connection']);
const connectionErrors = new WeakMap();
export async function connectionStep(stage, action) {
  if (!stages.has(stage)) throw new Error('Invalid diagnostic stage');
  try { return await action(); }
  catch (error) {
    const wrapped = new Error('Connection step failed');
    connectionErrors.set(wrapped, {stage, detail: safeDiagnostic(error)});
    throw wrapped;
  }
}
export function uiDiagnostic(error) {
  const connection = error && typeof error === 'object' ? connectionErrors.get(error) : undefined;
  if (connection) {
    return `Connection failed during ${connection.stage}: ${connection.detail}`;
  }
  return safeDiagnostic(error);
}
