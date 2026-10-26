"""Read indexed knowledge without loading an embedding model or invoking AI."""
from rag.query import _get_collection


def browse_chunks(*, query='', doc_type='', limit=25, offset=0):
    collection = _get_collection()
    filters = {}
    if query:
        filters['where_document'] = {'$contains': query}
    if doc_type:
        filters['where'] = {'type': doc_type}
    result = collection.get(limit=limit + 1, offset=offset,
                            include=['documents', 'metadatas'], **filters)
    rows = list(zip(result['ids'], result['documents'], result['metadatas']))
    return {
        'items': [{'id': key, 'metadata': meta or {}, 'preview': (text or '')[:220]}
                  for key, text, meta in rows[:limit]],
        'total_indexed': collection.count(),
        'next_offset': offset + limit if len(rows) > limit else None,
    }


def read_chunk(chunk_id):
    result = _get_collection().get(ids=[chunk_id], include=['documents', 'metadatas'])
    if not result['ids']:
        return None
    return {'id': result['ids'][0], 'text': result['documents'][0] or '',
            'metadata': result['metadatas'][0] or {}}
