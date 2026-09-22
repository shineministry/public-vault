/* =============================================================
   OFFLINE AI ENGINE — offline-ai.js
   v20260719-v2

   Complete offline AI system for the Online Vault:
     Phase 2: Cache document chunks in IndexedDB
     Phase 3: Download & cache SmolLM2 via Transformers.js
     Phase 4: Online AI (OpenAI/Gemini via backend — handled by auth.js)
     Phase 5: Automatic fallback (online → offline)
     Phase 6: Offline retrieval (chunk search → top 5 → SmolLM2)
     Phase 7: Synchronization (diff-based chunk updates)
     Phase 8: Startup logic (internet check, sync, load model)
     Phase 9: AI decision logic (question routing)

   IndexedDB stores used:
     ai_chunks   — document text chunks (key: chunkId)
     ai_models   — cached ML model files (key: modelId)
     ai_meta     — version tracking & sync state

   Public API:
     OfflineAI.init()                  — startup: check internet, sync, load model
     OfflineAI.ask(question)           — full pipeline: search → generate answer
     OfflineAI.isReady()               — true when model is loaded
     OfflineAI.getDownloadProgress()   — {downloaded, total} for progress UI
     OfflineAI.syncChunks(token)       — manual chunk sync trigger
     OfflineAI.getStats()              — {chunkCount, modelLoaded, lastSync}
   ============================================================= */

window.OfflineAI = (function () {
  'use strict';

  // ── Configuration ─────────────────────────────────────────────────────────
  const CONFIG = {
    DB_NAME: 'vaultOfflineAI',
    DB_VERSION: 1,

    // SmolLM2-135M-Instruct via Transformers.js (Hugging Face)
    // Small enough for browser (~260MB), still gives coherent answers
    MODEL_ID: 'Xenova/SmolLM2-135M-Instruct',
    MODEL_REVISION: 'main',

    // Chunk retrieval
    TOP_K: 5,              // number of chunks to retrieve per query
    CHUNK_SIZE: 800,       // must match backend chunking
    CHUNK_OVERLAP: 100,

    // Generation
    MAX_NEW_TOKENS: 256,
    TEMPERATURE: 0.3,
    TOP_P: 0.9,

    // Backend
    BACKEND_URL: 'https://backend.shinumaths989.workers.dev',

    // Timeouts
    SYNC_TIMEOUT: 30000,
    GENERATION_TIMEOUT: 60000,
  };

  // ── State ─────────────────────────────────────────────────────────────────
  let _db = null;
  let _model = null;
  let _tokenizer = null;
  let _modelReady = false;
  let _initDone = false;
  let _downloading = false;
  let _downloadProgress = { downloaded: 0, total: 0 };
  let _allChunks = [];   // in-memory cache of all chunks for search
  let _syncPromise = null;  // tracks the initial background sync so ask() can await it

  // ── IndexedDB Setup ───────────────────────────────────────────────────────

  function _openDB() {
    if (_db) return Promise.resolve(_db);
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(CONFIG.DB_NAME, CONFIG.DB_VERSION);

      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains('ai_chunks')) {
          var chunkStore = db.createObjectStore('ai_chunks', { keyPath: 'id' });
          chunkStore.createIndex('byFile', 'baseFileName', { unique: false });
          chunkStore.createIndex('byVersion', 'version', { unique: false });
        }
        if (!db.objectStoreNames.contains('ai_models')) {
          db.createObjectStore('ai_models', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('ai_meta')) {
          db.createObjectStore('ai_meta', { keyPath: 'key' });
        }
      };

      req.onsuccess = function () {
        _db = req.result;
        resolve(_db);
      };
      req.onerror = function () {
        reject(req.error);
      };
    });
  }

  // ── IndexedDB Helpers ─────────────────────────────────────────────────────

  async function _idbGet(storeName, key) {
    var db = await _openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var req = tx.objectStore(storeName).get(key);
      req.onsuccess = function () { resolve(req.result || null); };
      req.onerror = function () { reject(req.error); };
    });
  }

  async function _idbPut(storeName, value) {
    var db = await _openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).put(value);
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  async function _idbGetAll(storeName) {
    var db = await _openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var req = tx.objectStore(storeName).getAll();
      req.onsuccess = function () { resolve(req.result || []); };
      req.onerror = function () { reject(req.error); };
    });
  }

  async function _idbClear(storeName) {
    var db = await _openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      tx.objectStore(storeName).clear();
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  async function _idbCount(storeName) {
    var db = await _openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var req = tx.objectStore(storeName).count();
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  // ── Meta helpers ──────────────────────────────────────────────────────────

  async function _getMeta(key) {
    var row = await _idbGet('ai_meta', key);
    return row ? row.value : null;
  }

  async function _setMeta(key, value) {
    await _idbPut('ai_meta', { key: key, value: value, updatedAt: Date.now() });
  }

  // ── Phase 2: Cache Document Chunks ────────────────────────────────────────

  /**
   * Download all document chunks from Firestore and cache locally.
   * Uses version tracking to only download changed chunks.
   */
  async function syncChunks(token) {
    if (!token || token.startsWith('offline-')) {
      console.log('[OfflineAI] syncChunks: skipped (no valid token)');
      return { synced: 0, skipped: true };
    }

    console.log('[OfflineAI] syncChunks: starting chunk synchronization...');
    var synced = 0;
    var skipped = 0;
    var failed = 0;

    try {
      // Get the list of indexed files and their chunk counts from backend
      var statusRes = await fetch(CONFIG.BACKEND_URL + '/ai-chunk-status-all', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({})
      });

      if (!statusRes.ok) {
        console.warn('[OfflineAI] syncChunks: chunk status request failed (' + statusRes.status + ')');
        return { synced: 0, error: 'HTTP ' + statusRes.status };
      }

      var statusData = await statusRes.json();
      var files = statusData.files || statusData.indexed || [];

      // Get existing local versions
      var localMeta = await _getMeta('chunkVersions') || {};
      var needsSync = false;

      // For each file, download its chunks
      for (var i = 0; i < files.length; i++) {
        var fileName = files[i];
        try {
          // Check if we already have this file's chunks and they haven't changed
          // Backend doesn't provide per-file version yet, so we re-download all
          // This is fine — chunks are small text blobs (~800 chars each)

          // Download chunks for this file
          var chunkRes = await fetch(CONFIG.BACKEND_URL + '/ai-chunks', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({ baseFileName: fileName })
          });

          if (!chunkRes.ok) {
            failed++;
            continue;
          }

          var chunkData = await chunkRes.json();
          var chunks = chunkData.chunks || [];

          if (chunks.length === 0) {
            skipped++;
            continue;
          }

          // Check if chunks have changed
          var localVersion = localMeta[fileName] || 0;
          var remoteVersion = chunkData.version || Date.now();

          if (remoteVersion <= localVersion && chunks.length === (chunkData.localCount || chunks.length)) {
            skipped++;
            continue;
          }

          // Save chunks to IndexedDB
          for (var j = 0; j < chunks.length; j++) {
            var chunk = chunks[j];
            var chunkRecord = {
              id: fileName + '::chunk_' + (chunk.chunkIndex !== undefined ? chunk.chunkIndex : j),
              baseFileName: fileName,
              chunkIndex: chunk.chunkIndex !== undefined ? chunk.chunkIndex : j,
              totalChunks: chunk.totalChunks || chunks.length,
              text: chunk.chunkText || chunk.text || '',
              version: remoteVersion,
              savedAt: Date.now()
            };
            await _idbPut('ai_chunks', chunkRecord);
            synced++;
          }

          localMeta[fileName] = remoteVersion;
          needsSync = true;

        } catch (e) {
          console.warn('[OfflineAI] syncChunks: failed for "' + fileName + '":', e.message);
          failed++;
        }
      }

      // Save version tracking
      if (needsSync) {
        await _setMeta('chunkVersions', localMeta);
        await _setMeta('lastChunkSync', Date.now());
      }

      console.log('[OfflineAI] syncChunks done: ' + synced + ' synced, ' + skipped + ' skipped, ' + failed + ' failed');
      return { synced: synced, skipped: skipped, failed: failed };

    } catch (e) {
      console.error('[OfflineAI] syncChunks error:', e);
      return { synced: 0, error: e.message };
    }
  }

  /**
   * Load all cached chunks into memory for fast searching.
   */
  async function _loadChunksToMemory() {
    try {
      var allChunks = await _idbGetAll('ai_chunks');
      _allChunks = allChunks.filter(function (c) { return c.text && c.text.length > 10; });
      console.log('[OfflineAI] Loaded ' + _allChunks.length + ' chunks into memory');
    } catch (e) {
      console.warn('[OfflineAI] Failed to load chunks to memory:', e);
      _allChunks = [];
    }
  }

  // ── Phase 3: Download & Cache SmolLM2 ─────────────────────────────────────

  /**
   * Download the SmolLM2 model via Transformers.js and cache in IndexedDB.
   * Only happens once — subsequent loads use the cached copy.
   */
  async function _downloadAndCacheModel(progressCallback) {
    if (_downloading) return;
    _downloading = true;

    console.log('[OfflineAI] Downloading SmolLM2 model...');

    try {
      await _ensureTransformersLoaded();

      var cachedModel = await _idbGet('ai_models', CONFIG.MODEL_ID);
      if (cachedModel && cachedModel.loaded) {
        console.log('[OfflineAI] Model found in IndexedDB cache, restoring...');
        await _restoreModelFromCache(cachedModel);
        _modelReady = true;
        _downloading = false;
        return;
      }

      var pipeline = (window.Transformers || {}).pipeline;
      if (!pipeline) {
        throw new Error('Transformers.js pipeline not available');
      }

      _downloadProgress = { downloaded: 0, total: 0, files: {} };

      _model = await pipeline('text-generation', CONFIG.MODEL_ID, {
        progress_callback: function (progress) {
          if (progress.status === 'initiate') {
            console.log('[OfflineAI] Downloading:', progress.file || 'model');
          } else if (progress.status === 'progress') {
            if (progress.file) {
              _downloadProgress.files[progress.file] = progress.progress || 0;
            }
            var totalFiles = Object.keys(_downloadProgress.files).length;
            var completedFiles = Object.values(_downloadProgress.files).filter(function(v) { return v >= 100; }).length;
            _downloadProgress.downloaded = completedFiles;
            _downloadProgress.total = totalFiles;
            if (progressCallback) progressCallback(_downloadProgress);
          } else if (progress.status === 'done') {
            console.log('[OfflineAI] File downloaded:', progress.file || '');
          } else if (progress.status === 'ready') {
            console.log('[OfflineAI] Model ready');
          }
          console.log('[OfflineAI] Download event:', progress.status, progress.file || '');
        },
      });

      _modelReady = true;
      console.log('[OfflineAI] SmolLM2 model loaded successfully');

      await _idbPut('ai_models', {
        id: CONFIG.MODEL_ID,
        loaded: true,
        loadedAt: Date.now(),
        blobs: []
      });

    } catch (e) {
      console.error('[OfflineAI] Model download failed:', e);
      _modelReady = false;
      throw e;
    } finally {
      _downloading = false;
    }
  }

  async function _ensureTransformersLoaded() {
    if (window.Transformers && window.Transformers.pipeline) return;

    // Transformers.js v3 is ESM-only — use dynamic import() instead of script tag
    var mod = await import('https://cdn.jsdelivr.net/npm/@huggingface/transformers@3.5.1');
    if (!mod || !mod.pipeline) {
      throw new Error('Transformers.js loaded but pipeline export not found');
    }
    window.Transformers = mod;
  }

  async function _restoreModelFromCache(cachedModel) {
    await _ensureTransformersLoaded();
    var pipelineFn = (window.Transformers || {}).pipeline;
    if (!pipelineFn) throw new Error('pipeline function not available');
    _model = await pipelineFn('text-generation', CONFIG.MODEL_ID);
  }

  // ── Phase 6: Offline Retrieval (Chunk Search) ─────────────────────────────

  /**
   * Search cached chunks for the most relevant ones to a query.
   * Uses TF-IDF-like scoring without needing external libraries.
   */
  function _searchChunks(query, topK) {
    topK = topK || CONFIG.TOP_K;
    if (!_allChunks.length) return [];

    // Tokenize query
    var queryTerms = _tokenize(query);
    if (!queryTerms.length) return [];

    // Score each chunk
    var scored = [];
    for (var i = 0; i < _allChunks.length; i++) {
      var chunk = _allChunks[i];
      var score = _scoreChunk(chunk.text, queryTerms);
      if (score > 0) {
        scored.push({ chunk: chunk, score: score });
      }
    }

    // Sort by score descending
    scored.sort(function (a, b) { return b.score - a.score; });

    // Return top K
    return scored.slice(0, topK).map(function (s) { return s.chunk; });
  }

  /**
   * Fallback search: broader matching when strict search finds nothing.
   * Uses substring matching and always returns best-available chunks.
   */
  function _searchChunksBestEffort(query, topK) {
    topK = topK || CONFIG.TOP_K;
    if (!_allChunks.length) return [];

    var queryLower = query.toLowerCase().replace(/[^a-z0-9\s]/g, ' ').trim();
    var queryTerms = queryLower.split(/\s+/).filter(function (w) { return w.length > 2; });
    if (!queryTerms.length && queryLower.length > 2) {
      queryTerms = [queryLower];
    }
    if (!queryTerms.length) {
      // Absolute fallback: return the shortest (most focused) chunks
      return _allChunks.slice().sort(function (a, b) { return a.text.length - b.text.length; }).slice(0, topK);
    }

    // Score with substring matching — any chunk containing a query substring gets a score
    var scored = [];
    for (var i = 0; i < _allChunks.length; i++) {
      var chunk = _allChunks[i];
      var textLower = chunk.text.toLowerCase();
      var score = 0;
      for (var j = 0; j < queryTerms.length; j++) {
        if (textLower.indexOf(queryTerms[j]) !== -1) {
          score += 1;
        }
      }
      // Also check the full query as a phrase
      if (queryLower.length > 3 && textLower.indexOf(queryLower) !== -1) {
        score += 3;
      }
      if (score > 0) {
        scored.push({ chunk: chunk, score: score });
      }
    }

    if (scored.length === 0) {
      // Truly nothing matches — return the first few chunks as the best we have
      return _allChunks.slice(0, topK);
    }

    scored.sort(function (a, b) { return b.score - a.score; });
    return scored.slice(0, topK).map(function (s) { return s.chunk; });
  }

  /**
   * Tokenize text into lowercase words, removing stopwords.
   */
  function _tokenize(text) {
    var stopwords = {
      'a': 1, 'an': 1, 'the': 1, 'is': 1, 'are': 1, 'was': 1, 'were': 1,
      'be': 1, 'been': 1, 'being': 1, 'have': 1, 'has': 1, 'had': 1,
      'do': 1, 'does': 1, 'did': 1, 'will': 1, 'would': 1, 'could': 1,
      'should': 1, 'may': 1, 'might': 1, 'shall': 1, 'can': 1, 'to': 1,
      'of': 1, 'in': 1, 'for': 1, 'on': 1, 'with': 1, 'at': 1, 'by': 1,
      'from': 1, 'as': 1, 'into': 1, 'through': 1, 'during': 1, 'before': 1,
      'after': 1, 'and': 1, 'but': 1, 'or': 1, 'nor': 1, 'not': 1,
      'so': 1, 'yet': 1, 'both': 1, 'either': 1, 'neither': 1, 'each': 1,
      'every': 1, 'all': 1, 'any': 1, 'few': 1, 'more': 1, 'most': 1,
      'other': 1, 'some': 1, 'such': 1, 'no': 1, 'only': 1, 'own': 1,
      'same': 1, 'than': 1, 'too': 1, 'very': 1, 'just': 1, 'because': 1,
      'that': 1, 'this': 1, 'these': 1, 'those': 1, 'it': 1, 'its': 1,
      'i': 1, 'me': 1, 'my': 1, 'we': 1, 'our': 1, 'you': 1, 'your': 1,
      'he': 1, 'him': 1, 'his': 1, 'she': 1, 'her': 1, 'they': 1,
      'them': 1, 'their': 1, 'what': 1, 'which': 1, 'who': 1, 'whom': 1,
      'when': 1, 'where': 1, 'how': 1, 'if': 1, 'about': 1, 'up': 1,
      'out': 1, 'then': 1, 'once': 1, 'here': 1, 'there': 1, 'also': 1
    };

    return String(text).toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(function (w) { return w.length > 1 && !stopwords[w]; });
  }

  /**
   * Score a chunk against query terms using TF-IDF-like scoring.
   */
  function _scoreChunk(chunkText, queryTerms) {
    var textLower = chunkText.toLowerCase();
    var textTerms = _tokenize(chunkText);
    var textLen = textTerms.length || 1;

    // Build term frequency map for this chunk
    var tf = {};
    for (var i = 0; i < textTerms.length; i++) {
      var t = textTerms[i];
      tf[t] = (tf[t] || 0) + 1;
    }

    var score = 0;
    for (var j = 0; j < queryTerms.length; j++) {
      var term = queryTerms[j];

      // Term frequency in chunk (normalized)
      var termFreq = (tf[term] || 0) / textLen;

      // Exact phrase bonus
      var phraseMultiplier = 1;
      if (textLower.indexOf(term) !== -1) {
        phraseMultiplier = 1.5;
      }

      // IDF-like weight: rare terms get higher weight
      // Approximate: if term appears in <10% of chunks, boost it
      var docCount = 0;
      var totalCount = _allChunks.length || 1;
      for (var k = 0; k < _allChunks.length; k++) {
        if (_allChunks[k].text.toLowerCase().indexOf(term) !== -1) docCount++;
      }
      var idf = Math.log((totalCount + 1) / (docCount + 1)) + 1;

      score += termFreq * phraseMultiplier * idf;
    }

    // Bonus for shorter, more focused chunks (less noise)
    var lengthPenalty = Math.min(1, 500 / textLen);
    score *= (0.8 + 0.2 * lengthPenalty);

    return score;
  }

  // ── Phase 6: Offline Answer Generation ────────────────────────────────────

  /**
   * Generate an answer from the offline model using retrieved chunks as context.
   */
  async function _generateOfflineAnswer(question, chunks) {
    if (!_model || !_modelReady) {
      return 'Offline AI model is not loaded yet. Please connect to the internet and log in once to download the AI model.';
    }

    // Build context from retrieved chunks
    var contextParts = [];
    for (var i = 0; i < chunks.length; i++) {
      var c = chunks[i];
      contextParts.push('[Document: ' + c.baseFileName + ']\n' + c.text);
    }
    var context = contextParts.join('\n\n');

    // Build prompt in chat format (SmolLM2-Instruct format)
    var systemPrompt = 'You are a helpful AI assistant for a secure document vault. Answer questions based ONLY on the provided document excerpts. Be concise and accurate. If the documents don\'t contain enough information to answer, say so clearly.';

    var prompt = '<|system|>\n' + systemPrompt + '\n\nDocument Excerpts:\n' + context + '\n<|user|>\n' + question + '\n<|assistant|>\n';

    try {
      // Create a timeout promise
      var timeoutPromise = new Promise(function (_, reject) {
        setTimeout(function () { reject(new Error('Generation timed out')); }, CONFIG.GENERATION_TIMEOUT);
      });

      var generatePromise = _model(prompt, {
        max_new_tokens: CONFIG.MAX_NEW_TOKENS,
        temperature: CONFIG.TEMPERATURE,
        top_p: CONFIG.TOP_P,
        do_sample: CONFIG.TEMPERATURE > 0,
        return_full_text: false,
      });

      var result = await Promise.race([generatePromise, timeoutPromise]);

      // Extract generated text
      var reply = '';
      if (result && result[0]) {
        reply = result[0].generated_text || '';
      } else if (typeof result === 'string') {
        reply = result;
      }

      // Clean up the response
      reply = reply.trim();
      // Remove any trailing special tokens
      reply = reply.replace(/<\|.*?\|>/g, '').trim();

      if (!reply) {
        return 'I couldn\'t generate an answer from the available documents. The query may not match any stored content closely enough.';
      }

      return reply;

    } catch (e) {
      console.error('[OfflineAI] Generation error:', e);
      if (e.message && e.message.includes('timed out')) {
        return 'The AI model took too long to respond. Try a shorter or simpler question.';
      }
      return 'Error generating response: ' + (e.message || 'Unknown error');
    }
  }

  // ── Phase 5 & 9: Automatic Fallback & Decision Logic ──────────────────────

  /**
   * Main entry point: Answer a user question.
   * Tries online first (via backend), falls back to offline if needed.
   */
  async function ask(question, options) {
    options = options || {};
    var forceOffline = options.offline || false;

    // Phase 9: Check internet
    var isOnline = navigator.onLine && !forceOffline;

    // If an initial sync is still in progress, wait for it so chunks are available
    if (_syncPromise) {
      try { await _syncPromise; } catch (e) { /* sync failed, continue with whatever we have */ }
      _syncPromise = null;
    }

    if (isOnline) {
      // Phase 4: Try online AI first (via existing backend)
      try {
        var result = await _tryOnlineAI(question);
        if (result && result.success && result.reply) {
          return {
            answer: result.reply,
            source: 'online',
            success: true
          };
        }
      } catch (e) {
        console.log('[OfflineAI] Online AI failed, falling back to offline:', e.message);
      }
    }

    // Phase 5: Fallback to offline AI
    return await _answerOffline(question);
  }

  /**
   * Try the online AI via the existing backend endpoint.
   */
  async function _tryOnlineAI(question) {
    var token = sessionStorage.getItem('vaultSessionToken') ||
                sessionStorage.getItem('vaultSession') || '';

    if (!token || token.startsWith('offline-')) {
      return null;
    }

    var controller = new AbortController();
    var tid = setTimeout(function () { controller.abort(); }, 15000);

    try {
      var res = await fetch(CONFIG.BACKEND_URL + '/ai-search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ question: question }),
        signal: controller.signal
      });

      clearTimeout(tid);

      if (!res.ok) {
        return null;
      }

      var data = await res.json();
      return data;

    } catch (e) {
      clearTimeout(tid);
      throw e;
    }
  }

  /**
   * Answer using offline AI pipeline: search chunks → generate answer.
   */
  async function _answerOffline(question) {
    // Phase 6: Search cached chunks
    var chunks = _searchChunks(question, CONFIG.TOP_K);

    if (chunks.length === 0) {
      // If we're online and chunks are empty, try a sync before giving up
      if (navigator.onLine && _allChunks.length === 0) {
        var token = sessionStorage.getItem('vaultSessionToken') ||
                    sessionStorage.getItem('vaultSession') || '';
        if (token && !token.startsWith('offline-')) {
          console.log('[OfflineAI] No chunks in cache, attempting sync before answering...');
          try {
            await syncChunks(token);
            await _loadChunksToMemory();
            chunks = _searchChunks(question, CONFIG.TOP_K);
          } catch (e) {
            console.warn('[OfflineAI] Emergency sync failed:', e);
          }
        }
      }

      // If still no results, try a broader search (lower threshold, best-available)
      if (chunks.length === 0 && _allChunks.length > 0) {
        chunks = _searchChunksBestEffort(question, CONFIG.TOP_K);
      }

      if (chunks.length === 0) {
        return {
          answer: _allChunks.length === 0
            ? 'No documents have been synced to the offline cache yet. Please connect to the internet and log in to sync your vault documents for offline AI use.'
            : 'No relevant documents found for your question. Try rephrasing or using different keywords.',
          source: 'offline',
          success: true,
          chunksUsed: 0
        };
      }
    }

    // Phase 6: Generate answer from top chunks
    var answer = await _generateOfflineAnswer(question, chunks);

    return {
      answer: answer,
      source: 'offline',
      success: true,
      chunksUsed: chunks.length,
      chunks: chunks.map(function (c) { return { file: c.baseFileName, index: c.chunkIndex }; })
    };
  }

  // ── Phase 7: Synchronization ──────────────────────────────────────────────

  /**
   * Smart sync: compare server versions with local, download only changed chunks.
   * Called automatically when internet returns.
   */
  async function syncOnReconnect(token) {
    if (!navigator.onLine) return { synced: 0, skipped: true };

    console.log('[OfflineAI] Syncing chunks on reconnect...');
    return await syncChunks(token);
  }

  // ── Phase 8: Startup Logic ────────────────────────────────────────────────

  /**
   * Initialize the offline AI system.
   * Called once when the vault dashboard loads.
   */
  async function init(options) {
    options = options || {};

    if (_initDone) return;
    _initDone = true;

    console.log('[OfflineAI] Initializing offline AI system...');

    try {
      await _openDB();
      await _loadChunksToMemory();

      var chunkCount = _allChunks.length;
      console.log('[OfflineAI] ' + chunkCount + ' cached chunks available');

      var cachedModel = await _idbGet('ai_models', CONFIG.MODEL_ID);
      var modelCached = cachedModel && cachedModel.loaded;

      if (navigator.onLine) {
        var token = sessionStorage.getItem('vaultSessionToken') ||
                    sessionStorage.getItem('vaultSession') || '';

        // Phase 7: Sync chunks in background — show progress in offline toast
        if (token && !token.startsWith('offline-')) {
          if (typeof _showOfflineProgress === 'function') {
            _showOfflineProgress();
            _setOfflineProgressText('Syncing AI document chunks...');
            _updateOfflineProgress(0, 1);
          }
          _syncPromise = syncChunks(token).then(function (result) {
            console.log('[OfflineAI] Background chunk sync:', result);
            return _loadChunksToMemory().then(function() {
              if (modelCached) {
                if (typeof _setOfflineProgressDone === 'function') {
                  _setOfflineProgressDone('Document chunks synced ✓');
                }
              } else if (options.downloadModel !== false) {
                if (typeof _setOfflineProgressText === 'function') {
                  _setOfflineProgressText('Downloading AI model (~260 MB)...');
                  _updateOfflineProgress(0, 1);
                }
              }
              return result;
            });
          }).catch(function (e) {
            console.warn('[OfflineAI] Background sync failed:', e);
            if (modelCached) {
              if (typeof _setOfflineProgressDone === 'function') {
                _setOfflineProgressDone('Document chunks synced ✓');
              }
            }
          });
        }

        // Phase 3: Load model if not cached — auto-download on first login
        if (!modelCached && options.downloadModel !== false) {
          console.log('[OfflineAI] Model not cached, starting download...');
          if (typeof _showOfflineProgress === 'function') {
            _showOfflineProgress();
            _setOfflineProgressText('Downloading AI model (~260 MB)...');
            _updateOfflineProgress(0, 1);
          }
          _downloadAndCacheModel(function (progress) {
            var total = progress.total || 0;
            var done = progress.downloaded || 0;
            if (total > 0) {
              if (typeof _updateOfflineProgress === 'function') {
                _updateOfflineProgress(done, total);
              }
              if (typeof _setOfflineProgressText === 'function') {
                _setOfflineProgressText('Downloading AI model — ' + done + '/' + total + ' files...');
              }
            }
          }).then(function () {
            console.log('[OfflineAI] Model download complete');
            if (typeof _setOfflineProgressDone === 'function') {
              _setOfflineProgressDone('AI ready for offline use ✓');
            }
          }).catch(function (e) {
            console.error('[OfflineAI] Model download failed:', e);
            if (typeof _hideOfflineToast === 'function') {
              _hideOfflineToast();
            }
          });
        } else if (modelCached) {
          console.log('[OfflineAI] Restoring model from cache...');
          try {
            await _restoreModelFromCache(cachedModel);
            _modelReady = true;
            console.log('[OfflineAI] Model restored successfully');
          } catch (e) {
            console.warn('[OfflineAI] Model restore failed, will re-download:', e);
          }
        }
      } else {
        if (modelCached) {
          try {
            await _restoreModelFromCache(cachedModel);
            _modelReady = true;
            console.log('[OfflineAI] Model loaded from cache (offline)');
          } catch (e) {
            console.warn('[OfflineAI] Model restore failed:', e);
          }
        } else {
          console.warn('[OfflineAI] No cached model available offline');
        }
      }

      window.addEventListener('online', function () {
        console.log('[OfflineAI] Back online — syncing...');
        var token = sessionStorage.getItem('vaultSessionToken') ||
                    sessionStorage.getItem('vaultSession') || '';
        if (token && !token.startsWith('offline-')) {
          syncOnReconnect(token);
        }
      });

      console.log('[OfflineAI] Initialization complete. Model ready:', _modelReady, '| Chunks:', chunkCount);

    } catch (e) {
      console.error('[OfflineAI] Initialization error:', e);
    }
  }

  // ── Public API ────────────────────────────────────────────────────────────

  function isReady() {
    return _modelReady && _allChunks.length > 0;
  }

  function getDownloadProgress() {
    return Object.assign({}, _downloadProgress);
  }

  async function getStats() {
    var chunkCount = _allChunks.length;
    var lastSync = await _getMeta('lastChunkSync');
    var modelInfo = await _idbGet('ai_models', CONFIG.MODEL_ID);

    return {
      chunkCount: chunkCount,
      modelLoaded: _modelReady,
      modelCached: !!(modelInfo && modelInfo.loaded),
      lastSync: lastSync,
      downloading: _downloading,
      downloadProgress: _downloadProgress,
      totalFilesIndexed: Object.keys(
        _allChunks.reduce(function (acc, c) { acc[c.baseFileName] = true; return acc; }, {})
      ).length
    };
  }

  async function startModelDownload(progressCallback) {
    return await _downloadAndCacheModel(progressCallback);
  }

  // ── Return public interface ───────────────────────────────────────────────

  return {
    init: init,
    ask: ask,
    isReady: isReady,
    getDownloadProgress: getDownloadProgress,
    getStats: getStats,
    syncChunks: syncChunks,
    syncOnReconnect: syncOnReconnect,
    startModelDownload: startModelDownload,
    searchChunks: _searchChunks,  // exposed for debugging
    CONFIG: CONFIG
  };

})();
