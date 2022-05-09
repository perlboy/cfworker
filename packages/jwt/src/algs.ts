export const algToHash: Record<string, string> = {
  RS256: 'SHA-256',
  RS384: 'SHA-384',
  RS512: 'SHA-512'
};

export const algs = Object.keys(algToHash);

/**
 * "Next Gen" algorithms map, need to refactor old alg stuff above
 */
export const algorithms: {
  [key: string]:
    | AlgorithmIdentifier
    | RsaPssParams
    | EcdsaParams
    | EcKeyImportParams;
} = {
  ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
  ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } },
  ES512: { name: 'ECDSA', namedCurve: 'P-512', hash: { name: 'SHA-512' } },
  HS256: { name: 'HMAC', hash: { name: 'SHA-256' } },
  HS384: { name: 'HMAC', hash: { name: 'SHA-384' } },
  HS512: { name: 'HMAC', hash: { name: 'SHA-512' } },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
  RS384: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } },
  RS512: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } }
};
