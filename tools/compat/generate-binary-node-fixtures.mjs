#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const SCHEMA = 'wa-binary-node-fixture-v1'

const samples = [
  {
    name: 'iq_ping',
    node: {
      tag: 'iq',
      attrs: {
        to: 's.whatsapp.net',
        type: 'get',
      },
      content: [{ tag: 'ping' }],
    },
  },
  {
    name: 'message_enc',
    node: {
      tag: 'message',
      attrs: {
        from: '12345@s.whatsapp.net',
        id: 'ABCDEF123',
        type: 'text',
      },
      content: [
        {
          tag: 'enc',
          attrs: { type: 'pkmsg' },
          content: { bytes_hex: '0102030405' },
        },
      ],
    },
  },
  {
    name: 'retry_receipt',
    node: {
      tag: 'receipt',
      attrs: {
        from: '123:1@s.whatsapp.net',
        id: 'retry-1',
        type: 'retry',
      },
      content: [
        {
          tag: 'retry',
          attrs: {
            count: '2',
            error: '7',
          },
        },
        {
          tag: 'registration',
          content: { bytes_hex: '01020304' },
        },
      ],
    },
  },
  {
    name: 'presence_device',
    node: {
      tag: 'presence',
      attrs: {
        from: '123:7@s.whatsapp.net',
        name: 'Desk Agent',
        to: 'status@broadcast',
        type: 'available',
      },
    },
  },
  {
    name: 'app_state_sync_query',
    node: {
      tag: 'iq',
      attrs: {
        id: 'app-state-1',
        to: 's.whatsapp.net',
        type: 'get',
        xmlns: 'w:sync:app:state',
      },
      content: [
        {
          tag: 'sync',
          attrs: { version: '2' },
          content: [
            {
              tag: 'collection',
              attrs: { name: 'regular_high', version: '42' },
            },
            {
              tag: 'collection',
              attrs: { name: 'regular_low', version: '7' },
            },
          ],
        },
      ],
    },
  },
  {
    name: 'history_sync_notification',
    node: {
      tag: 'notification',
      attrs: {
        from: 's.whatsapp.net',
        id: 'hist-1',
        type: 'server_sync',
      },
      content: [
        {
          tag: 'history',
          attrs: {
            'chunk-order': '1',
            progress: '80',
          },
          content: { bytes_hex: '08011204deadbeef1a0548656c6c6f' },
        },
      ],
    },
  },
  {
    name: 'media_message_attrs',
    node: {
      tag: 'message',
      attrs: {
        from: '12345@s.whatsapp.net',
        id: 'MEDIA123',
        to: '67890@s.whatsapp.net',
        type: 'media',
      },
      content: [
        {
          tag: 'enc',
          attrs: {
            type: 'msg',
            v: '2',
          },
          content: { bytes_hex: '00112233445566778899aabbccddeeff' },
        },
        {
          tag: 'media',
          attrs: {
            direct_path: '/v/t62.7118-24/example',
            filehash: 'ABCDEF0123456789',
            media_key_timestamp: '1700000000',
            type: 'image',
            url: 'https://mmg.whatsapp.net/v/t62.7118-24/example',
          },
        },
      ],
    },
  },
  {
    name: 'group_participant_notification',
    node: {
      tag: 'notification',
      attrs: {
        from: '11111-22222@g.us',
        id: 'group-1',
        type: 'w:gp2',
      },
      content: [
        {
          tag: 'participant',
          attrs: {
            jid: '123:1@s.whatsapp.net',
            type: 'add',
          },
        },
        {
          tag: 'participant',
          attrs: {
            jid: 'abc@lid',
            type: 'remove',
          },
        },
      ],
    },
  },
  {
    name: 'usync_query',
    node: {
      tag: 'iq',
      attrs: {
        id: 'usync-1',
        to: 's.whatsapp.net',
        type: 'get',
        xmlns: 'usync',
      },
      content: [
        {
          tag: 'usync',
          attrs: {
            context: 'interactive',
            index: '0',
            last: 'true',
            mode: 'query',
            sid: 'abc123',
          },
          content: [
            {
              tag: 'query',
              content: [
                { tag: 'contact' },
                { tag: 'status' },
                { tag: 'devices' },
              ],
            },
            {
              tag: 'list',
              content: [
                {
                  tag: 'user',
                  attrs: { jid: '12345@s.whatsapp.net' },
                },
                {
                  tag: 'user',
                  attrs: { jid: 'abc@lid' },
                },
              ],
            },
          ],
        },
      ],
    },
  },
  {
    name: 'jid_device_domains',
    node: {
      tag: 'iq',
      attrs: {
        id: 'jid-domains-1',
        to: 's.whatsapp.net',
        type: 'set',
        xmlns: 'usync',
      },
      content: [
        {
          tag: 'usync',
          content: [
            {
              tag: 'list',
              content: [
                {
                  tag: 'user',
                  attrs: { jid: 'abc:7@lid' },
                },
                {
                  tag: 'user',
                  attrs: { jid: '321:9@hosted' },
                },
                {
                  tag: 'user',
                  attrs: { jid: 'def:10@hosted.lid' },
                },
              ],
            },
          ],
        },
      ],
    },
  },
  {
    name: 'stream_error_text',
    node: {
      tag: 'stream:error',
      attrs: { code: '515' },
      content: [
        {
          tag: 'conflict',
          content: { text: '515' },
        },
      ],
    },
  },
  {
    name: 'receipt_list_items',
    node: {
      tag: 'receipt',
      attrs: {
        from: '11111-22222@g.us',
        id: 'msg-1',
        participant: '123@s.whatsapp.net',
        type: 'read',
      },
      content: [
        {
          tag: 'list',
          content: [
            {
              tag: 'item',
              attrs: { id: 'a' },
            },
            {
              tag: 'item',
              attrs: {
                id: 'b',
                participant: '123:1@s.whatsapp.net',
                t: '1700000001',
              },
            },
          ],
        },
      ],
    },
  },
  {
    name: 'call_offer',
    node: {
      tag: 'call',
      attrs: {
        from: '12345@s.whatsapp.net',
        id: 'call-1',
      },
      content: [
        {
          tag: 'offer',
          attrs: {
            'call-creator': '12345@s.whatsapp.net',
            'call-id': 'call-1',
            type: 'audio',
          },
          content: [
            {
              tag: 'audio',
              attrs: {
                enc: 'opus',
                rate: '16000',
              },
            },
          ],
        },
      ],
    },
  },
]

const options = parseArgs(process.argv.slice(2))
if (options.help || !options.referenceModule || !options.out) {
  printUsage()
  process.exit(options.help ? 0 : 2)
}

const referenceModulePath = resolve(options.referenceModule)
const referenceModule = await import(pathToFileURL(referenceModulePath).href)
const encodeBinaryNode =
  referenceModule.encodeBinaryNode ?? referenceModule.default?.encodeBinaryNode

if (typeof encodeBinaryNode !== 'function') {
  throw new Error(
    `reference module ${referenceModulePath} must export encodeBinaryNode`,
  )
}

const fixtures = samples.map((sample) => {
  const referenceNode = toReferenceNode(sample.node)
  const encoded = encodeBinaryNode(referenceNode)
  return {
    name: sample.name,
    encoded_hex: Buffer.from(encoded).toString('hex'),
    node: sample.node,
  }
})

const manifest = {
  schema: SCHEMA,
  source: `reference-module:${referenceModulePath}`,
  fixtures,
}

const out = resolve(options.out)
await mkdir(dirname(out), { recursive: true })
await writeFile(out, `${JSON.stringify(manifest, null, 2)}\n`)

function toReferenceNode(node) {
  const out = {
    tag: node.tag,
  }
  if (node.attrs) {
    out.attrs = node.attrs
  }
  if ('content' in node) {
    out.content = toReferenceContent(node.content)
  }
  return out
}

function toReferenceContent(content) {
  if (Array.isArray(content)) {
    return content.map(toReferenceNode)
  }
  if (content && typeof content === 'object' && 'bytes_hex' in content) {
    return Buffer.from(content.bytes_hex, 'hex')
  }
  if (content && typeof content === 'object' && 'text' in content) {
    return content.text
  }
  return content
}

function parseArgs(args) {
  const parsed = {
    referenceModule: process.env.WA_REFERENCE_BINARY_MODULE,
    out: 'tests/fixtures/binary_nodes/manifest.json',
    help: false,
  }
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (arg === '--help' || arg === '-h') {
      parsed.help = true
    } else if (arg === '--reference-module') {
      parsed.referenceModule = args[++index]
    } else if (arg === '--out') {
      parsed.out = args[++index]
    } else {
      throw new Error(`unknown argument: ${arg}`)
    }
  }
  return parsed
}

function printUsage() {
  console.error(`Usage:
  node tools/compat/generate-binary-node-fixtures.mjs \\
    --reference-module /path/to/reference/wabinary-module.js \\
    --out tests/fixtures/binary_nodes/manifest.json

The reference module must export encodeBinaryNode(node). The script writes the
fixture manifest schema consumed by wa-testkit.`)
}
