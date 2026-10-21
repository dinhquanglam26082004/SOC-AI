"""Only cite documents that are actually placed in the bounded prompt."""
import os


def bounded_context(documents):
    budget = int(os.getenv('AI_CONTEXT_CHARS', '6000'))
    blocks, citations = [], []
    for doc in documents:
        meta = doc.get('metadata', {})
        header = '[SOURCE ' + str(meta.get('source', len(blocks) + 1))[:150] + ']\n'
        remaining = budget - sum(len(b) for b in blocks)
        if remaining <= len(header) + 32:
            break
        block = header + doc['text'][:remaining - len(header) - 2] + '\n\n'
        blocks.append(block)
        citations.append(meta)
    return ''.join(blocks), citations
