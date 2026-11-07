/**
 * Transport registry.
 *
 * A transport is one self-contained channel through which a stored credential can be
 * used. index.js keeps the security core (storage, redaction, use limits, approval,
 * guard, management API) and hands each transport a narrow `host` object; the transport
 * owns its protocol policy and its model-facing tool definition.
 *
 * Adding a channel should be: create one module under this directory, export a factory
 * `(host) => transport`, and add that factory to the list passed to
 * `createTransportRegistry` in index.js. The registry itself and index.js do not need
 * protocol-specific branches.
 *
 * Transport shape:
 *   {
 *     id: 'http',
 *     label: 'HTTP(S) proxy',
 *     policyFields: ['hosts', 'methods'],       // immutable credential fields it reads
 *     actions: [{ id, summary }],               // for vault_transports introspection
 *     tools: [toolDefinition],                  // model-facing tools registered as-is
 *     artifact?: {
 *       sources: [{ id, summary }],
 *       read({ item, source, maxBytes, signal, exec }) -> { data: Buffer, filename?, contentType? }
 *     }
 *   }
 *
 * `host` is provided by index.js and is documented in index.js; it never exposes the
 * raw vault object, only item lookups, redaction, use accounting and the artifact sink.
 */

export function createTransportRegistry(host, factories) {
  const transports = new Map()
  for (const factory of factories) {
    const transport = factory(host)
    if (transport === null || typeof transport !== 'object') throw new Error('transport factory 必须返回对象')
    if (typeof transport.id !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(transport.id)) {
      throw new Error(`transport id 不合法：${String(transport.id)}`)
    }
    if (transports.has(transport.id)) throw new Error(`transport id 重复：${transport.id}`)
    transports.set(transport.id, transport)
  }

  const artifactTransports = () => [...transports.values()].filter((transport) => transport.artifact)

  return {
    all() {
      return [...transports.values()]
    },
    get(id) {
      return transports.get(String(id ?? ''))
    },
    tools() {
      return [...transports.values()].flatMap((transport) => (Array.isArray(transport.tools) ? transport.tools : []))
    },
    describe() {
      return [...transports.values()].map((transport) => ({
        id: transport.id,
        label: transport.label,
        policyFields: Array.isArray(transport.policyFields) ? [...transport.policyFields] : [],
        actions: Array.isArray(transport.actions) ? transport.actions.map((action) => ({ ...action })) : [],
        artifactSources: transport.artifact && Array.isArray(transport.artifact.sources)
          ? transport.artifact.sources.map((source) => ({ ...source }))
          : [],
      }))
    },
    async readArtifact({ item, source, maxBytes, signal, exec }) {
      const transportId = String(source?.transport ?? '')
      const transport = transports.get(transportId)
      if (transport === undefined) {
        throw new Error(`未知 transport：${transportId || '（空）'}；可用：${[...transports.keys()].join(', ')}`)
      }
      if (!transport.artifact || typeof transport.artifact.read !== 'function') {
        throw new Error(`transport ${transportId} 不支持落盘取数`)
      }
      return await transport.artifact.read({ item, source, maxBytes, signal, exec })
    },
  }
}

/** Model-facing introspection: which channels exist and what they can do. */
export function createTransportsTool(registry) {
  return {
    name: 'vault_transports',
    description: 'List the transport channels this vault supports, the immutable credential policy fields each one uses, and the actions / artifact sources each one exposes. Static metadata only; no credential value is read.',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: {
        type: 'object',
        properties: {
          transports: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                label: { type: 'string' },
                policyFields: { type: 'array', items: { type: 'string' } },
                actions: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: { id: { type: 'string' }, summary: { type: 'string' } },
                    required: ['id'],
                    additionalProperties: false,
                  },
                },
                artifactSources: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: { id: { type: 'string' }, summary: { type: 'string' } },
                    required: ['id'],
                    additionalProperties: false,
                  },
                },
              },
              required: ['id', 'label'],
              additionalProperties: false,
            },
          },
          note: { type: 'string' },
        },
        required: ['transports'],
        additionalProperties: false,
      },
      render: (_args, value) => {
        const lines = ['可用通道（只读内省，不读取凭证值）：']
        for (const transport of Array.isArray(value?.transports) ? value.transports : []) {
          lines.push(`- ${transport.id} [${transport.label}] policy=${transport.policyFields.join('|') || '—'}`)
          for (const action of transport.actions ?? []) lines.push(`  action: ${action.id}${action.summary ? ` — ${action.summary}` : ''}`)
          for (const source of transport.artifactSources ?? []) lines.push(`  artifact: ${source.id}${source.summary ? ` — ${source.summary}` : ''}`)
        }
        if (value?.note) lines.push('', value.note)
        return [{ type: 'text', text: lines.join('\n') }]
      },
    },
    async execute() {
      return {
        transports: registry.describe(),
        note: 'Use vault_save({ id, source, dir?, filename?, maxBytes?, overwrite? }) with source.transport set to one of the artifact-capable ids.',
      }
    },
  }
}
