// Smoke test for the browser package, run under Node after `./build.sh nodejs`:
//   node test/smoke.mjs
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { preparePrivatePost } = require('../pkg-nodejs/kryphocron_web.js');

const did = 'did:plc:exampleexampleexample';
const nsid = 'tools.kryphocron.feed.postPrivate';
const rkey = '3kabcdefghij2';
const blob = { $type: 'blob', ref: { $link: 'bafyimg' }, mimeType: 'image/jpeg', size: 10 };
const content = JSON.stringify({
  text: 'hello @friend',
  facets: [{ index: { byteStart: 6, byteEnd: 13 },
    features: [{ $type: 'app.bsky.richtext.facet#mention', did: 'did:plc:friend' }] }],
  embed: { $type: 'app.bsky.embed.images', images: [{ alt: '', image: blob }] },
});
const now = Math.floor(Date.now() / 1000);

const a = JSON.parse(preparePrivatePost(did, nsid, rkey, content, now));
const b = JSON.parse(preparePrivatePost(did, nsid, rkey, content, now));

assert.equal(a.encodedContentCodec, 'laquna/0.2');
assert.match(a.encodedContentGeneration, new RegExp(`^laquna/${String(now).padStart(20, '0')}/[0-9a-f]{64}$`));
assert.equal(typeof a.encodedContent.$bytes, 'string');
assert.notEqual(a.encodedContent.$bytes, b.encodedContent.$bytes, 'each encode differs');
assert.deepEqual(a.mentionDids, ['did:plc:friend']);
assert.deepEqual(a.mediaKinds, ['image']);
assert.deepEqual(a.embedBlobs, [blob]);
assert.equal(a.quote, undefined);
assert.equal(a.text, undefined);

assert.throws(() => preparePrivatePost('plc:x', nsid, rkey, content, now));
assert.throws(() => preparePrivatePost(did, nsid, rkey, '{"facets":[]}', now));
assert.throws(() => preparePrivatePost(did, nsid, rkey, content, Number.NaN));

console.log('smoke: ok');
