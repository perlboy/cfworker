import { algorithms } from './algs';
import { base64url } from 'rfc4648';

/**
 * At the moment this is really only targeted at support HMAC secret key based signing
 * @param payload
 * @param secret
 * @param alg
 */
export async function signJwt(
  payload: { [k: string]: any },
  secret: string,
  alg = 'HS256'
): Promise<String> {
  const importAlgorithm = algorithms[alg];
  if (!importAlgorithm) throw new Error('algorithm not found');
  payload.iat = Math.floor(Date.now() / 1000);
  const payloadAsJSON = JSON.stringify(payload);
  const partialToken = `${base64url.stringify(
    _utf8ToUint8Array(
      JSON.stringify({
        alg: alg
      })
    ),
    { pad: false }
  )}.${base64url.stringify(_utf8ToUint8Array(payloadAsJSON), { pad: false })}`;
  const keyData = _utf8ToUint8Array(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    importAlgorithm,
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    importAlgorithm,
    key,
    _utf8ToUint8Array(partialToken)
  );
  return `${partialToken}.${base64url.stringify(new Uint8Array(signature), {
    pad: false
  })}`;
}

function _utf8ToUint8Array(str: string) {
  return base64url.parse(btoa(decodeURIComponent(encodeURIComponent(str))));
}
