class FireSenseCrunch {
  constructor(options = {}) {
    // Configuration defaults
    this.config = {
      maxFileSize: 50 * 1024 * 1024, // 50MB
      allowedTypes: [
        'image/*',
        'video/*',
        'audio/*',
        'font/*',
        'text/css',
        'application/javascript'
      ],
      binaryFormats: [
        'image/png',
        'image/jpeg',
        'image/gif',
        'image/webp',
        'image/svg+xml',
        'video/mp4',
        'video/webm',
        'audio/mpeg',
        'font/woff',
        'font/woff2'
      ],
      cacheTTL: 3600 * 1000, // 1 hour
      ...options
    };

    // Internal state
    this.cache = new Map();
    this.pendingRequests = new Map();
    this.resourceRegistry = new Map();
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
    this.initPerformanceMonitor();
  }

  /**
   * Initialize performance monitoring
   */
  initPerformanceMonitor() {
    this.performanceMetrics = {
      totalResourcesProcessed: 0,
      totalBytesProcessed: 0,
      cacheHits: 0,
      cacheMisses: 0,
      startTime: performance.now()
    };

    // Periodic metric reporter
    this.metricInterval = setInterval(() => {
      console.debug('[Crunch Metrics]', {
        uptime: ((performance.now() - this.performanceMetrics.startTime) / 1000).toFixed(2) + 's',
        ...this.performanceMetrics
      });
    }, 30000);
  }

  /**
   * Main crunch method - converts URL to loadable module
   * @param {string} url - Resource URL to crunch
   * @param {object} options - Processing options
   * @returns {Promise<CrunchResult>}
   */
  async crunch(url, options = {}) {
    const startTime = performance.now();
    const cacheKey = this.generateCacheKey(url, options);

    // Check cache first
    if (this.cache.has(cacheKey)) {
      this.performanceMetrics.cacheHits++;
      const cached = this.cache.get(cacheKey);
      if (cached.expiry > Date.now()) {
        return cached.result;
      }
      this.cache.delete(cacheKey);
    }

    this.performanceMetrics.cacheMisses++;

    // Deduplicate concurrent requests
    if (this.pendingRequests.has(cacheKey)) {
      return this.pendingRequests.get(cacheKey);
    }

    const requestPromise = this.processResource(url, options)
      .then(result => {
        this.cache.set(cacheKey, {
          result,
          expiry: Date.now() + this.config.cacheTTL
        });
        this.pendingRequests.delete(cacheKey);
        return result;
      })
      .catch(err => {
        this.pendingRequests.delete(cacheKey);
        throw err;
      });

    this.pendingRequests.set(cacheKey, requestPromise);

    const result = await requestPromise;
    const processingTime = performance.now() - startTime;

    this.performanceMetrics.totalResourcesProcessed++;
    this.performanceMetrics.totalBytesProcessed += result.size;

    console.debug(`[Crunch] Processed ${url} in ${processingTime.toFixed(2)}ms`);

    return result;
  }

  /**
   * Core resource processing pipeline
   */
  async processResource(url, options) {
    // Phase 1: Fetch with timeout
    const response = await this.fetchWithTimeout(url, options.timeout || 10000);

    // Phase 2: Validate response
    this.validateResponse(response);

    // Phase 3: Process based on content type
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    const contentLength = parseInt(response.headers.get('content-length')) || 0;

    if (this.isBinaryContentType(contentType)) {
      return this.processBinaryResource(response, url, contentType, options);
    } else {
      return this.processTextResource(response, url, contentType, options);
    }
  }

  /**
   * Process binary resources (images, videos, fonts, etc.)
   */
  async processBinaryResource(response, url, contentType, options) {
    const buffer = await response.arrayBuffer();
    const uint8Array = new Uint8Array(buffer);

    // Create resource fingerprint
    const fingerprint = await this.createResourceFingerprint(uint8Array);
    const base64Data = this.arrayBufferToBase64(uint8Array);

    return {
      type: 'binary',
      url,
      contentType,
      size: buffer.byteLength,
      data: base64Data,
      fingerprint,
      module: this.generateBinaryModule(url, base64Data, contentType, fingerprint),
      css: this.generateCSSAsset(url, base64Data, contentType),
      dependencies: []
    };
  }

  /**
   * Process text resources (JS, CSS, etc.)
   */
  async processTextResource(response, url, contentType, options) {
    const text = await response.text();
    const fingerprint = await this.createResourceFingerprint(this.encoder.encode(text));

    // Parse for dependencies if JS/CSS
    const dependencies = [];
    if (contentType.includes('javascript')) {
      dependencies.push(...this.extractJsDependencies(text));
    } else if (contentType.includes('css')) {
      dependencies.push(...this.extractCssDependencies(text, url));
    }

    return {
      type: 'text',
      url,
      contentType,
      size: text.length,
      data: text,
      fingerprint,
      module: this.generateTextModule(url, text, contentType, fingerprint),
      css: null,
      dependencies
    };
  }

  /**
   * Generate JavaScript module for binary resources
   */
  generateBinaryModule(url, base64Data, contentType, fingerprint) {
    const resourceName = this.generateResourceName(url);
    const mimeType = contentType.split(';')[0];

    return `// FireSense Crunch Module - ${url}
const ${resourceName} = {
  type: '${mimeType}',
  data: 'data:${mimeType};base64,${base64Data}',
  fingerprint: '${fingerprint}',
  size: ${base64Data.length},
  toString() { return this.data; }
};

${this.generateTypeDeclarations(resourceName, mimeType)}

export default ${resourceName};
export const dataURL = ${resourceName}.data;
export const fingerprint = '${fingerprint}';`;
  }

  /**
   * Generate JavaScript module for text resources
   */
  generateTextModule(url, text, contentType, fingerprint) {
    const resourceName = this.generateResourceName(url);
    const sanitizedText = this.sanitizeTextContent(text);
    const mimeType = contentType.split(';')[0];

    return `// FireSense Crunch Module - ${url}
const ${resourceName} = ${this.wrapTextContent(sanitizedText, mimeType)};

${this.generateTypeDeclarations(resourceName, mimeType)}

export default ${resourceName};
export const source = ${resourceName}.source;
export const fingerprint = '${fingerprint}';`;
  }

  /**
   * Generate CSS asset for binary resources
   */
  generateCSSAsset(url, base64Data, contentType) {
    const resourceName = this.generateResourceName(url, true);
    const mimeType = contentType.split(';')[0];

    if (mimeType.startsWith('font')) {
      return `@font-face {
  font-family: '${resourceName}';
  src: url('data:${mimeType};base64,${base64Data}') format('${this.getFontFormat(mimeType)}');
}`;
    } else if (mimeType.startsWith('image')) {
      return `.${resourceName}-bg {
  background-image: url('data:${mimeType};base64,${base64Data}');
}`;
    }
    return null;
  }

  /** Helper Methods */

  async fetchWithTimeout(url, timeout) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        signal: controller.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      });
      clearTimeout(timeoutId);
      return response;
    } catch (err) {
      clearTimeout(timeoutId);
      throw new Error(`Fetch timed out after ${timeout}ms`);
    }
  }

  validateResponse(response) {
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} - ${response.statusText}`);
    }

    const contentType = response.headers.get('content-type') || '';
    const contentLength = parseInt(response.headers.get('content-length')) || 0;

    if (contentLength > this.config.maxFileSize) {
      throw new Error(`Resource exceeds maximum size (${this.config.maxFileSize} bytes)`);
    }

    const isAllowed = this.config.allowedTypes.some(pattern => {
      if (pattern.endsWith('/*')) {
        return contentType.startsWith(pattern.replace('/*', ''));
      }
      return contentType === pattern;
    });

    if (!isAllowed) {
      throw new Error(`Content type ${contentType} not allowed`);
    }
  }

  isBinaryContentType(contentType) {
    return this.config.binaryFormats.some(pattern => {
      if (pattern.endsWith('/*')) {
        return contentType.startsWith(pattern.replace('/*', ''));
      }
      return contentType === pattern;
    });
  }

  async createResourceFingerprint(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  generateResourceName(url, forCSS = false) {
    const urlObj = new URL(url);
    let name = urlObj.hostname.replace(/\./g, '_') + 
               urlObj.pathname.replace(/[^a-zA-Z0-9]/g, '_');
    
    if (forCSS) {
      name = name.replace(/^_+/, '').replace(/_+/g, '-').toLowerCase();
    }
    
    return name;
  }

  sanitizeTextContent(text) {
    return text
      .replace(/\\/g, '\\\\')
      .replace(/`/g, '\\`')
      .replace(/\${/g, '\\${');
  }

  wrapTextContent(text, mimeType) {
    if (mimeType.includes('javascript')) {
      return `{\n  source: \`${text}\`,\n  execute: () => {\n    const script = document.createElement('script');\n    script.textContent = this.source;\n    document.head.appendChild(script);\n  }\n}`;
    } else if (mimeType.includes('css')) {
      return `{\n  source: \`${text}\`,\n  inject: () => {\n    const style = document.createElement('style');\n    style.textContent = this.source;\n    document.head.appendChild(style);\n  }\n}`;
    } else {
      return `{\n  source: \`${text}\`\n}`;
    }
  }

  generateTypeDeclarations(name, mimeType) {
    if (mimeType.includes('javascript')) {
      return `/** @type {{ source: string, execute: () => void }} */`;
    } else if (mimeType.includes('css')) {
      return `/** @type {{ source: string, inject: () => void }} */`;
    } else if (mimeType.startsWith('image')) {
      return `/** @type {{ type: string, data: string, fingerprint: string, size: number }} */`;
    } else {
      return `/** @type {{ source: string }} */`;
    }
  }

  getFontFormat(mimeType) {
    const formats = {
      'font/woff': 'woff',
      'font/woff2': 'woff2',
      'font/ttf': 'truetype',
      'font/otf': 'opentype'
    };
    return formats[mimeType] || mimeType.split('/')[1];
  }

  extractJsDependencies(code) {
    const imports = [];
    // Match ES6 imports
    const importRegex = /import\s+(?:.*?\s+from\s+)?["']([^"']+)["']/g;
    let match;
    while ((match = importRegex.exec(code))) {
      imports.push(match[1]);
    }
    // Match CommonJS requires
    const requireRegex = /require\(["']([^"']+)["']\)/g;
    while ((match = requireRegex.exec(code))) {
      imports.push(match[1]);
    }
    return imports.filter(url => this.isExternalUrl(url));
  }

  extractCssDependencies(code, baseUrl) {
    const urls = [];
    // Match url() references
    const urlRegex = /url\(["']?([^"')]+)["']?\)/g;
    let match;
    while ((match = urlRegex.exec(code))) {
      if (this.isExternalUrl(match[1])) {
        urls.push(new URL(match[1], baseUrl).toString());
      }
    }
    // Match @import rules
    const importRegex = /@import\s+(?:url\()?["']([^"')]+)["']\)?/g;
    while ((match = importRegex.exec(code))) {
      if (this.isExternalUrl(match[1])) {
        urls.push(new URL(match[1], baseUrl).toString());
      }
    }
    return urls;
  }

  isExternalUrl(url) {
    return url.startsWith('http://') || 
           url.startsWith('https://') || 
           url.startsWith('//');
  }

  generateCacheKey(url, options) {
    const { excludeHeaders = [], ...rest } = options;
    const sortedOptions = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('&');
    return `${url}?${sortedOptions}`;
  }

  // Advanced utility methods
  async crunchAll(urls, options = {}) {
    const results = [];
    for (const url of urls) {
      try {
        results.push(await this.crunch(url, options));
      } catch (err) {
        console.error(`Failed to crunch ${url}:`, err);
        results.push(null);
      }
    }
    return results;
  }

  async crunchDependencies(resource, depth = 1) {
    if (depth < 0) return resource;
    
    const dependencies = resource.dependencies || [];
    const depResults = await Promise.all(
      dependencies.map(depUrl => this.crunch(depUrl, { depth: depth - 1 }))
    );
    
    return {
      ...resource,
      dependencies: depResults
    };
  }

  // Cache management
  clearCache() {
    this.cache.clear();
    this.performanceMetrics.cacheHits = 0;
    this.performanceMetrics.cacheMisses = 0;
  }

  // Cleanup
  destroy() {
    clearInterval(this.metricInterval);
    this.clearCache();
    this.pendingRequests.clear();
  }
}

// Browser and Node.js compatible export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FireSenseCrunch;
} else {
  window.FireSenseCrunch = FireSenseCrunch;
}
